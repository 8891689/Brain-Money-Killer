/*
 * This file is based on the original work by vladkens, with modifications.
 * The original license and copyright for the base software are preserved below.
 * 
 * Modifications made by the contributor at:
 * https://github.com/8891689
 */

/* --- Original License and Copyright Notice --- */
/*MIT License

Copyright (c) 2024 vladkens

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.*/

#include <locale.h>
#include <string.h>
#include <stdalign.h>

#include "lib/addr.c"
#include "lib/bench.c"
#include "lib/ecc.c" 
#include "lib/utils.c"

// https://github.com/8891689
#include "lib/sha256_avx.h"
#include "lib/ripemd160_avx.h"

#define VERSION ".8891689"
#define GROUP_INV_SIZE 1024
#define MAX_LINE_SIZE 128
#define RAW_BATCH_SIZE 8 
#define MAX_JOB_SIZE (1024 * 1024 * 2)

enum Cmd { CMD_NIL, CMD_ADD, CMD_MUL };

typedef struct ctx_t {
  enum Cmd cmd;
  pthread_mutex_t lock;
  size_t threads_count;
  pthread_t *threads;
  size_t k_checked;
  size_t k_found;
  size_t stime;
  bool check_addr33;
  bool check_addr65;
  FILE *outfile;
  bool quiet;
  bool use_bloom;
  bool use_confirm;
  h160_t *to_find_hashes;
  size_t to_find_count;
  blf_t blf;
  
  fe range_s;
  fe range_e;
  pe gpoints[GROUP_INV_SIZE];
  u64 job_size;
  
  queue_t queue;
  bool raw_text;
} ctx_t;


typedef struct cmd_mul_job_t {
  size_t count;
  char lines[GROUP_INV_SIZE][MAX_LINE_SIZE];
} cmd_mul_job_t;

// Reimplementation and modification ：https://github.com/8891689
void load_bloom(ctx_t *ctx, const char *filepath) {
  if (!filepath) { fprintf(stderr, "missing bloom filter file (-b)\n"); exit(1); }
  if (!blf_load(filepath, &ctx->blf)) { fprintf(stderr, "failed to load bloom filter: %s\n", filepath); exit(1); }
  ctx->use_bloom = true;
}

// Reimplementation and modification ：https://github.com/8891689
void load_hash_list(ctx_t *ctx, const char *filepath) {
  if (!filepath) { fprintf(stderr, "missing hash list file (-f)\n"); exit(1); }
  FILE *file = fopen(filepath, "r");
  if (!file) { fprintf(stderr, "failed to open hash list file: %s\n", filepath); exit(1); }
  size_t capacity = 32, size = 0;
  u32 *hashes = malloc(capacity * sizeof(u32) * 5);
  if (hashes == NULL) { fprintf(stderr, "Error: Failed to allocate initial memory for hash list.\n"); exit(1); }
  hex40 line;
  while (fgets(line, sizeof(line), file)) {
    if (strlen(line) != sizeof(line) - 1) continue;
    if (size >= capacity) {
      capacity *= 2;
      u32 *new_hashes = realloc(hashes, capacity * sizeof(u32) * 5);
      if (new_hashes == NULL) {
          fprintf(stderr, "Error: Failed to reallocate memory for hash list. Out of memory?\n");
          free(hashes);
          exit(1);
      }
      hashes = new_hashes;
    }
    for (size_t j = 0; j < sizeof(line) - 1; j += 8) {
      sscanf(line + j, "%8x", &hashes[size * 5 + j / 8]);
    }
    size += 1;
  }
  fclose(file);
  qsort(hashes, size, 5 * sizeof(u32), compare_160);
  ctx->to_find_hashes = (h160_t *)hashes;
  ctx->to_find_count = size;
  ctx->use_confirm = true;
}

void ctx_print_status(ctx_t *ctx) {
  pthread_mutex_lock(&ctx->lock);
  double dt = (tsnow() - ctx->stime) / 1000.0;
  double it = (dt > 0) ? (ctx->k_checked / dt / 1000000) : 0;
  printf("\r%.2fs ~ %.2fM it/s ~ %'zu / %'zu", dt, it, ctx->k_found, ctx->k_checked);
  fflush(stdout);
  pthread_mutex_unlock(&ctx->lock);
}

void ctx_write_found(ctx_t *ctx, const char *label, const h160_t hash, const fe pk) {
  pthread_mutex_lock(&ctx->lock);
  if (!ctx->quiet) {
    printf("\r%s: %08x%08x%08x%08x%08x <- %016llx%016llx%016llx%016llx\n",
           label, hash[0], hash[1], hash[2], hash[3], hash[4], pk[3], pk[2], pk[1], pk[0]);
  }
  if (ctx->outfile != NULL) {
    fprintf(ctx->outfile, "%s\t%08x%08x%08x%08x%08x\t%016llx%016llx%016llx%016llx\n",
            label, hash[0], hash[1], hash[2], hash[3], hash[4], pk[3], pk[2], pk[1], pk[0]);
    fflush(ctx->outfile);
  }
  pthread_mutex_unlock(&ctx->lock);
}


bool ctx_check_hash(ctx_t *ctx, const h160_t h) {
  if (ctx->use_bloom && ctx->use_confirm) {
    if (blf_has(&ctx->blf, h)) {
      return bsearch(h, ctx->to_find_hashes, ctx->to_find_count, sizeof(h160_t), compare_160) != NULL;
    }
    return false;// https://github.com/8891689
  } else if (ctx->use_bloom) {
    return blf_has(&ctx->blf, h);
  } else if (ctx->use_confirm) {
    return bsearch(h, ctx->to_find_hashes, ctx->to_find_count, sizeof(h160_t), compare_160) != NULL;
  }
  return false;
}

// Reimplementation and modification ：https://github.com/8891689
void *cmd_add_worker(void *arg) {
    ctx_t *ctx = (ctx_t *)arg;
    Sha256Avx8_C_Handle* sha_hasher = sha256_avx8_create();
    alignas(64) RIPEMD160_MULTI_CTX ripemd_ctx;
    if (!sha_hasher) { return NULL; }

    fe current_pk;
    u64 task_size;

    while (true) {
        pthread_mutex_lock(&ctx->lock);
        if (fe_cmp(ctx->range_s, ctx->range_e) >= 0) {
            pthread_mutex_unlock(&ctx->lock);
            break;
        }
        fe_clone(current_pk, ctx->range_s);
        fe task_end;
        fe_clone(task_end, ctx->range_s);
        fe_add64(task_end, ctx->job_size);
        if (fe_cmp(task_end, ctx->range_e) > 0) fe_clone(task_end, ctx->range_e);
        fe task_size_fe;
        fe_modsub(task_size_fe, task_end, current_pk);
        task_size = task_size_fe[0];
        fe_clone(ctx->range_s, task_end);
        pthread_mutex_unlock(&ctx->lock);

        if (task_size == 0) continue;

        u64 found_in_job = 0;
        u64 iterations_done = 0;
        
        pe start_point;
        pe *bp = malloc(GROUP_INV_SIZE * sizeof(pe));
        ec_gtable_mul(&start_point, current_pk);
        
        pe giant_step_G;
        ec_gtable_mul(&giant_step_G, (fe){GROUP_INV_SIZE, 0, 0, 0});

        while(iterations_done < task_size) {
            u64 current_round_size = MIN(GROUP_INV_SIZE, task_size - iterations_done);
            
            for (u64 i = 0; i < current_round_size; ++i) {
                ec_jacobi_add(&bp[i], &start_point, &ctx->gpoints[i]);
            }

            ec_jacobi_grprdc(bp, current_round_size);

            for (u64 j = 0; j < current_round_size; j += RAW_BATCH_SIZE) {
                int current_batch_size = (current_round_size - j < RAW_BATCH_SIZE) ? (current_round_size - j) : RAW_BATCH_SIZE;
                
                fe temp_pk;
                if (ctx->check_addr33) {
                    alignas(32) h160_t hash_results[RAW_BATCH_SIZE];
                    addrs33_avx2_batch(hash_results, &bp[j], sha_hasher, &ripemd_ctx);
                    for (int k = 0; k < current_batch_size; ++k) {
                        if (ctx_check_hash(ctx, hash_results[k])) {
                            fe_clone(temp_pk, current_pk);
                            fe_add64(temp_pk, iterations_done + j + k + 1);
                            ctx_write_found(ctx, "addr33", hash_results[k], temp_pk);
                            found_in_job++;
                        }
                    }
                }
                if (ctx->check_addr65) {
                    alignas(32) h160_t hash_results[RAW_BATCH_SIZE];
                    addrs65_avx2_batch(hash_results, &bp[j], sha_hasher, &ripemd_ctx);
                    for (int k = 0; k < current_batch_size; ++k) {
                        if (ctx_check_hash(ctx, hash_results[k])) {
                           fe_clone(temp_pk, current_pk);
                           fe_add64(temp_pk, iterations_done + j + k + 1);
                           ctx_write_found(ctx, "addr65", hash_results[k], temp_pk);
                           found_in_job++;
                        }
                    }
                }
            }
            
            ec_jacobi_add(&start_point, &start_point, &giant_step_G);
            iterations_done += current_round_size;
        }
        
        free(bp);

        pthread_mutex_lock(&ctx->lock);
        ctx->k_checked += task_size;
        ctx->k_found += found_in_job;
        pthread_mutex_unlock(&ctx->lock);
        ctx_print_status(ctx);
    }
    sha256_avx8_destroy(sha_hasher);
    return NULL;
}

// Reimplementation and modification ：https://github.com/8891689
int cmd_add(ctx_t *ctx) {
  ec_gtable_init();
  pe_clone(&ctx->gpoints[0], &G1);
  for (u64 i = 1; i < GROUP_INV_SIZE; ++i) {
    ec_jacobi_add(&ctx->gpoints[i], &ctx->gpoints[i - 1], &G1);
  }
  ec_jacobi_grprdc(ctx->gpoints, GROUP_INV_SIZE);

  fe range_size;
  fe_modsub(range_size, ctx->range_e, ctx->range_s);
  ctx->job_size = fe_cmp64(range_size, MAX_JOB_SIZE) < 0 ? range_size[0] : MAX_JOB_SIZE;

  for (size_t i = 0; i < ctx->threads_count; ++i) {
    pthread_create(&ctx->threads[i], NULL, cmd_add_worker, ctx);
  }
  for (size_t i = 0; i < ctx->threads_count; ++i) {
    pthread_join(ctx->threads[i], NULL);
  }
  ctx_print_status(ctx);
  printf("\n");
  return 0;
}

// Reimplementation and modification ：https://github.com/8891689
void *cmd_mul_worker(void *arg) {
    ctx_t *ctx = (ctx_t *)arg;
    Sha256Avx8_C_Handle* sha_hasher = sha256_avx8_create();
    alignas(64) RIPEMD160_MULTI_CTX ripemd_ctx;
    if (!sha_hasher) { return NULL; }
    
    cmd_mul_job_t *job = NULL;
    while (true) {
        if (job != NULL) free(job);
        job = queue_get(&ctx->queue);
        if (job == NULL) break;
        size_t found_in_job = 0;
        if (ctx->raw_text) {
             for (size_t i = 0; i < job->count; i += RAW_BATCH_SIZE) {
                int current_batch_size = (job->count - i < RAW_BATCH_SIZE) ? (job->count - i) : RAW_BATCH_SIZE;
                alignas(64) uint8_t blocks[RAW_BATCH_SIZE][64];
                alignas(32) uint8_t digests[RAW_BATCH_SIZE][32];
                for (int j = 0; j < current_batch_size; ++j) {
                    const char* line = job->lines[i + j];
                    size_t len = strlen(line);
                    if (len >= 56) { prepare_test_data_block(blocks[j], "", 0); } 
                    else { prepare_test_data_block(blocks[j], line, len); }
                }
                for (int j = current_batch_size; j < RAW_BATCH_SIZE; ++j) { prepare_test_data_block(blocks[j], "", 0); }
                sha256_avx8_init(sha_hasher);
                sha256_avx8_update_8_blocks(sha_hasher, blocks);
                sha256_avx8_get_final_hashes(sha_hasher, digests);
                alignas(32) pe cp_batch[RAW_BATCH_SIZE];
                alignas(32) fe pk_batch[RAW_BATCH_SIZE];
                for (int j = 0; j < current_batch_size; ++j) {
                    if (strlen(job->lines[i+j]) >= 56) continue;
                    for (int k = 0; k < 4; ++k) {
                        pk_batch[j][k] = ((u64)digests[j][(3-k)*8+0] << 56) | ((u64)digests[j][(3-k)*8+1] << 48) | ((u64)digests[j][(3-k)*8+2] << 40) | ((u64)digests[j][(3-k)*8+3] << 32) | ((u64)digests[j][(3-k)*8+4] << 24) | ((u64)digests[j][(3-k)*8+5] << 16) | ((u64)digests[j][(3-k)*8+6] << 8)  | ((u64)digests[j][(3-k)*8+7]);
                    }
                }
                for (int j = 0; j < current_batch_size; ++j) {
                     if (strlen(job->lines[i+j]) >= 56) continue;
                     ec_gtable_mul(&cp_batch[j], pk_batch[j]);
                }
                ec_jacobi_grprdc(cp_batch, current_batch_size);
                if (ctx->check_addr33) {
                    alignas(32) h160_t hash_results[RAW_BATCH_SIZE];
                    addrs33_avx2_batch(hash_results, cp_batch, sha_hasher, &ripemd_ctx);
                    for (int j = 0; j < current_batch_size; ++j) {
                        if (strlen(job->lines[i+j]) >= 56) continue;
                        if (ctx_check_hash(ctx, hash_results[j])) {
                            ctx_write_found(ctx, "addr33", hash_results[j], pk_batch[j]);
                            found_in_job++;
                        }
                    }
                }
                if (ctx->check_addr65) {
                    alignas(32) h160_t hash_results[RAW_BATCH_SIZE];
                    addrs65_avx2_batch(hash_results, cp_batch, sha_hasher, &ripemd_ctx);
                    for (int j = 0; j < current_batch_size; ++j) {
                        if (strlen(job->lines[i+j]) >= 56) continue;
                        if (ctx_check_hash(ctx, hash_results[j])) {
                            ctx_write_found(ctx, "addr65", hash_results[j], pk_batch[j]);
                            found_in_job++;
                        }
                    }
                }
            }
        } else {
            for (size_t i = 0; i < job->count; i += RAW_BATCH_SIZE) {
                int current_batch_size = (job->count - i < RAW_BATCH_SIZE) ? (job->count - i) : RAW_BATCH_SIZE;
                alignas(32) pe cp_batch[RAW_BATCH_SIZE];
                alignas(32) fe pk_batch[RAW_BATCH_SIZE];
                for (int j = 0; j < current_batch_size; ++j) fe_from_hex(pk_batch[j], job->lines[i + j]);
                for (int j = 0; j < current_batch_size; ++j) ec_gtable_mul(&cp_batch[j], pk_batch[j]);
                ec_jacobi_grprdc(cp_batch, current_batch_size);
                 if (ctx->check_addr33) {
                    alignas(32) h160_t hash_results[RAW_BATCH_SIZE];
                    addrs33_avx2_batch(hash_results, cp_batch, sha_hasher, &ripemd_ctx);
                    for (int j = 0; j < current_batch_size; ++j) {
                        if (ctx_check_hash(ctx, hash_results[j])) {
                            ctx_write_found(ctx, "addr33", hash_results[j], pk_batch[j]);
                            found_in_job++;
                        }
                    }
                }
                if (ctx->check_addr65) {
                    alignas(32) h160_t hash_results[RAW_BATCH_SIZE];
                    addrs65_avx2_batch(hash_results, cp_batch, sha_hasher, &ripemd_ctx);
                    for (int j = 0; j < current_batch_size; ++j) {
                        if (ctx_check_hash(ctx, hash_results[j])) {
                            ctx_write_found(ctx, "addr65", hash_results[j], pk_batch[j]);
                            found_in_job++;
                        }
                    }
                }
            }
        }
        pthread_mutex_lock(&ctx->lock);
        ctx->k_checked += job->count;
        ctx->k_found += found_in_job;
        pthread_mutex_unlock(&ctx->lock);
        if(job->count > 0) {
            ctx_print_status(ctx);
        }
    }
    if (job != NULL) free(job);
    sha256_avx8_destroy(sha_hasher);
    return NULL;
}


int cmd_mul(ctx_t *ctx) {
  ec_gtable_init();
  for (size_t i = 0; i < ctx->threads_count; ++i) {
    pthread_create(&ctx->threads[i], NULL, cmd_mul_worker, ctx);
  }
  cmd_mul_job_t *job = calloc(1, sizeof(cmd_mul_job_t));
  char line[MAX_LINE_SIZE];
  while (fgets(line, sizeof(line), stdin) != NULL) {
    size_t len = strlen(line);
    if (len > 0 && line[len - 1] == '\n') line[--len] = '\0';
    if (len > 0 && line[len - 1] == '\r') line[--len] = '\0';
    if (len == 0) continue;
    strcpy(job->lines[job->count++], line);
    if (job->count == GROUP_INV_SIZE) {
      queue_put(&ctx->queue, job);
      job = calloc(1, sizeof(cmd_mul_job_t));
    }
  }
  if (job->count > 0) { queue_put(&ctx->queue, job); }
  else { free(job); }
  
  queue_done(&ctx->queue);
  for (size_t i = 0; i < ctx->threads_count; ++i) {
    pthread_join(ctx->threads[i], NULL);
  }
  ctx_print_status(ctx);
  printf("\n");
  return 0;
}


void arg_search_range(args_t *args, fe range_s, fe range_e) {
  char *raw = arg_str(args, "-r");
  if (!raw) {
    fprintf(stderr, "Error: 'puzzle' command requires a range specified with -r (e.g., -r 1:FFFF)\n");
    exit(1);
  }
  // https://github.com/8891689
  char *sep = strchr(raw, ':');
  if (!sep) {
    fprintf(stderr, "invalid search range, use format: -r start:end\n");
    exit(1);
  }
  *sep = 0;
  const char* start_str = raw;
  const char* end_str = sep + 1;
  if (strlen(start_str) == 0 || strlen(end_str) == 0) {
      fprintf(stderr, "invalid search range: start or end value is missing.\n");
      exit(1);
  }
  fe_from_hex(range_s, start_str);
  fe_from_hex(range_e, end_str);
  if (fe_iszero(range_s)) {
      fe_set64(range_s, 1);
  }
  if (fe_cmp(range_e, P) > 0) {
    fe_clone(range_e, P);
  }
  if (fe_cmp(range_s, range_e) >= 0) {
    fprintf(stderr, "invalid search range, start must be less than end.\n");
    exit(1);
  }
}

void usage(const char *name) {
    printf("Usage: %s <cmd> [-t <threads>] [-b <bloom_file>] [-f <hash_list>] [-a <addr_type>] [-r <range>] [-sha]\n", name);
    printf("v%s\n", VERSION);
    printf("\nCompute commands:\n");
    printf("  puzzle          - Performs efficient search within a given range, suitable for puzzle games.\n");
    printf("  brain           - Search from standard input. Defaults to a hexadecimal private key; brainwallet attacks require the -sha flag.\n");
    printf("\nCompute options:\n");
    printf("  -b <file>       - bloom filter file\n");
    printf("  -f <file>       - hash list file for second confirmation\n");
    printf("  -o <file>       - output file (default: stdout)\n");
    printf("  -t <threads>    - number of threads to run (default: 1)\n");
    printf("  -a <addr_type>  - address type to search: c addr33(compressed), u addr65(uncompressed), (default: c)\n");
    printf("  -r <range>      - (for puzzle mode) search range in hex format (example: 8000:ffff)\n");
    printf("  -q              - quiet mode (no stdout; must use -o)\n");
    printf("  -sha            - (For brainwallet mode) Treats the standard input line as a raw text password and encrypts the computed private key using SHA256.\n");
}

void init(ctx_t *ctx, args_t *args) {
    if (args->argc > 1) { if (strcmp(args->argv[1], "bloom") == 0) { blf_gen(args); exit(0); } }
    
    ctx->cmd = CMD_NIL;
    if (args->argc > 1) {
        if (strcmp(args->argv[1], "puzzle") == 0) ctx->cmd = CMD_ADD;
        if (strcmp(args->argv[1], "brain") == 0) ctx->cmd = CMD_MUL;
    }
    
    if (ctx->cmd == CMD_NIL) {
        if (args_bool(args, "-v")) printf("Brainmk v%s\n", VERSION);
        else usage(args->argv[0]);
        exit(0);
    }
    
    ctx->use_bloom = false; ctx->use_confirm = false;
    char *bloom_path = arg_str(args, "-b");
    if (bloom_path) { load_bloom(ctx, bloom_path); }
    char *hash_path = arg_str(args, "-f");
    if (hash_path) { load_hash_list(ctx, hash_path); }
    
    ctx->quiet = args_bool(args, "-q");
    char *outfile = arg_str(args, "-o");
    if (outfile) ctx->outfile = fopen(outfile, "a");
    if (outfile == NULL && ctx->quiet) { fprintf(stderr, "quiet mode chosen without output file\n"); exit(1); }
    
    char *addr = arg_str(args, "-a");
    if (addr) {
        ctx->check_addr33 = strstr(addr, "c") != NULL;
        ctx->check_addr65 = strstr(addr, "u") != NULL;
    } else {
        ctx->check_addr33 = true;
        ctx->check_addr65 = false;
    }
    
    pthread_mutex_init(&ctx->lock, NULL);
    ctx->threads_count = MIN(MAX(args_int(args, "-t", 1), 1), 128);
    ctx->threads = malloc(ctx->threads_count * sizeof(pthread_t));
    ctx->k_checked = 0; ctx->k_found = 0;
    ctx->stime = tsnow();
    
    if (ctx->cmd == CMD_ADD) {
        arg_search_range(args, ctx->range_s, ctx->range_e);
    }
    if (ctx->cmd == CMD_MUL) {
        queue_init(&ctx->queue, ctx->threads_count * 3);
        ctx->raw_text = args_bool(args, "-sha");
    }

    printf("command: %s | threads: %zu | addr33: %d | addr65: %d\n", 
           ctx->cmd == CMD_ADD ? "puzzle" : "brain", ctx->threads_count, ctx->check_addr33, ctx->check_addr65);

    if (ctx->cmd == CMD_MUL && ctx->raw_text) { printf("Mode: brainwallet password (enter < 56 characters)\n"); }
    
    if (ctx->use_bloom && ctx->use_confirm) { printf("filter: bloom + list (%'zu)\n", ctx->to_find_count); }
    else if (ctx->use_bloom) { printf("filter: bloom\n"); }
    else if (ctx->use_confirm) { printf("filter: list (%'zu)\n", ctx->to_find_count); }
    else { printf("filter: none\n"); }
    
    if (ctx->cmd == CMD_ADD) {
      fe_print("range_s", ctx->range_s);
      fe_print("range_e", ctx->range_e);
    }
    printf("----------------------------------------\n");
}

int main(int argc, const char **argv) {
  // https://stackoverflow.com/a/11695246
  setlocale(LC_NUMERIC, "");
  args_t args = {argc, argv};
  ctx_t ctx = {0};
  
  init(&ctx, &args);
  
  if (ctx.cmd == CMD_ADD) {
      cmd_add(&ctx);
  }
  
  if (ctx.cmd == CMD_MUL) {
      cmd_mul(&ctx);
  }
  
  if (ctx.outfile != NULL) fclose(ctx.outfile);
  return 0;
}
