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
#include <gmp.h> 

#include "lib/addr.h"
#include "lib/bench.h"
#include "lib/ecc.h" 
#include "lib/utils.h"
// https://github.com/8891689
#include "bitrange.h" 
#include "random.h"   
#include "sha256_avx.h"
#include "ripemd160_avx.h"

#include <stdatomic.h>
#include <byteswap.h> 
#include <unistd.h>

#define VERSION "8891689"
#define GROUP_INV_SIZE 1024
#define MAX_LINE_SIZE 128
#define RAW_BATCH_SIZE 8 
#define MAX_JOB_SIZE (1024 * 1024 * 2)
#define RANDOM_JUMP_INTERVAL 1000000ULL

enum Mode { MODE_NIL, MODE_PUZZLE, MODE_BRAIN };

typedef struct ctx_t {
  enum Mode mode;
  pthread_mutex_t lock;
  size_t threads_count;
  pthread_t *threads;
  _Atomic size_t k_checked; 
  _Atomic size_t k_found;   
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
  
  mpz_t gmp_range_s;
  mpz_t gmp_range_e;
  mpz_t gmp_curve_n;

  pe gpoints[GROUP_INV_SIZE];
  u64 job_size;
  
  queue_t queue;
  bool raw_text;

  bool random_mode;
  
} ctx_t;


typedef struct cmd_mul_job_t {
  size_t count;
  char lines[GROUP_INV_SIZE][MAX_LINE_SIZE];
} cmd_mul_job_t;

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
    size_t current_checked = atomic_load(&ctx->k_checked);
    size_t current_found = atomic_load(&ctx->k_found);
    
    double dt = (tsnow() - ctx->stime) / 1000.0;
    
    double it = (dt > 0) ? (current_checked / dt / 1000000) : 0;
    
#if defined(_WIN32) || defined(_WIN64)
    printf("\r[+] Total %.2fs ~ %.2fM it/s ~ %llu / %llu",
           dt, it,
           (unsigned long long)current_found,
           (unsigned long long)current_checked);
#else
    printf("\r[+] Total %.2fs ~ %.2fM it/s ~ %'zu / %'zu",
           dt, it, current_found, current_checked);
#endif

    printf(" "); 
    fflush(stdout);
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
    return false;
  } else if (ctx->use_bloom) {
    return blf_has(&ctx->blf, h);
  } else if (ctx->use_confirm) {
    return bsearch(h, ctx->to_find_hashes, ctx->to_find_count, sizeof(h160_t), compare_160) != NULL;
  }
  return false;
}
// Reimplementation and modification ：https://github.com/8891689
void fe_from_mpz(fe r, const mpz_t m) {
    unsigned char be_buffer[32] = {0};
    size_t count;
    mpz_export(be_buffer, &count, 1, 1, 1, 0, m);

    if (count > 0 && count < 32) {
        memmove(be_buffer + 32 - count, be_buffer, count);
        memset(be_buffer, 0, 32 - count);
    }
    u64* r_ptr = (u64*)r;
    for (int i = 0; i < 4; ++i) {
        memcpy(&r_ptr[i], &be_buffer[32 - (i + 1) * 8], 8);
        r_ptr[i] = bswap_64(r_ptr[i]);
    }
}
// Reimplementation and modification ：https://github.com/8891689
void *cmd_puzzle_worker(void *arg) {
    ctx_t *ctx = (ctx_t *)arg;
    Sha256Avx8_C_Handle *sha_hasher = sha256_avx8_create();
    alignas(64) RIPEMD160_MULTI_CTX ripemd_ctx;
    if (!sha_hasher) { return NULL; }

    mpz_t task_start_pk_mpz;
    fe current_pk_fe;
    u64 task_size;
    mpz_init(task_start_pk_mpz);

    if (ctx->random_mode) {
        pthread_t tid = pthread_self();
        rseed(time(NULL) ^ (uintptr_t)tid);
    }

    while (true) {
        if (ctx->random_mode) {
            mpz_t range_size, random_offset;
            mpz_init(range_size);
            mpz_init(random_offset);

            mpz_sub(range_size, ctx->gmp_range_e, ctx->gmp_range_s);
            if (mpz_cmp_ui(range_size, 0) <= 0) {
                mpz_clear(range_size);
                mpz_clear(random_offset);
                break; 
            }

            unsigned char rand_bytes[32];
            for(int i = 0; i < 8; ++i) {
                uint32_t r = rndu32();
                memcpy(rand_bytes + i*4, &r, 4);
            }
            mpz_import(random_offset, 32, 1, sizeof(unsigned char), 0, 0, rand_bytes);
            mpz_mod(random_offset, random_offset, range_size);
            mpz_add(task_start_pk_mpz, ctx->gmp_range_s, random_offset);
            task_size = ctx->job_size;

            mpz_clear(range_size);
            mpz_clear(random_offset);
        } else {
            pthread_mutex_lock(&ctx->lock);
            if (mpz_cmp(ctx->gmp_range_s, ctx->gmp_range_e) >= 0) {
                pthread_mutex_unlock(&ctx->lock);
                break;
            }
            mpz_set(task_start_pk_mpz, ctx->gmp_range_s);
            mpz_add_ui(ctx->gmp_range_s, ctx->gmp_range_s, ctx->job_size);
            task_size = ctx->job_size;
            pthread_mutex_unlock(&ctx->lock);
        }

        mpz_t task_end_pk_mpz, remaining;
        mpz_init(task_end_pk_mpz);
        mpz_init(remaining);
        mpz_add_ui(task_end_pk_mpz, task_start_pk_mpz, task_size);

        if (mpz_cmp(task_end_pk_mpz, ctx->gmp_range_e) > 0) {
             mpz_sub(remaining, ctx->gmp_range_e, task_start_pk_mpz);
             if(mpz_fits_ulong_p(remaining)) {
                 task_size = mpz_get_ui(remaining);
             } else {
                 task_size = 0;
             }
        }
        mpz_clear(task_end_pk_mpz);
        mpz_clear(remaining);
        
        if (task_size == 0) continue;

        fe_from_mpz(current_pk_fe, task_start_pk_mpz);
        
        pe start_point;
        pe *bp = malloc(GROUP_INV_SIZE * sizeof(pe));
        if (!bp) continue;
        
        ec_gtable_mul(&start_point, current_pk_fe);
        
        pe giant_step_G;
        fe fe_group_inv_size;
        fe_set64(fe_group_inv_size, GROUP_INV_SIZE);
        ec_gtable_mul(&giant_step_G, fe_group_inv_size);

        u64 iterations_done = 0;
        while(iterations_done < task_size) {
            u64 current_round_size = MIN(GROUP_INV_SIZE, task_size - iterations_done);
            u64 found_this_round = 0;

            for (u64 i = 0; i < current_round_size; ++i) {
                ec_jacobi_add(&bp[i], &start_point, &ctx->gpoints[i]);
            }
            ec_jacobi_grprdc(bp, current_round_size);

            for (u64 j = 0; j < current_round_size; j += RAW_BATCH_SIZE) {
                int current_batch_size = MIN(RAW_BATCH_SIZE, current_round_size - j);
                fe temp_pk_fe;
                if (ctx->check_addr33) {
                    alignas(32) h160_t hash_results[RAW_BATCH_SIZE];
                    addrs33_avx2_batch(hash_results, &bp[j], sha_hasher, &ripemd_ctx);
                    for (int k = 0; k < current_batch_size; ++k) {
                        if (ctx_check_hash(ctx, hash_results[k])) {
                            fe_clone(temp_pk_fe, current_pk_fe);
                            fe_add64(temp_pk_fe, iterations_done + j + k + 1); 
                            ctx_write_found(ctx, "addr33", hash_results[k], temp_pk_fe);
                            found_this_round++;
                        }
                    }
                }
            }
            ec_jacobi_add(&start_point, &start_point, &giant_step_G);
            iterations_done += current_round_size;

            atomic_fetch_add(&ctx->k_checked, current_round_size);
            if (found_this_round > 0) {
                atomic_fetch_add(&ctx->k_found, found_this_round);
            }
        }
        
        free(bp);
    }

    mpz_clear(task_start_pk_mpz);
    sha256_avx8_destroy(sha_hasher);
    return NULL;
}


// Reimplementation and modification ：https://github.com/8891689
int cmd_puzzle(ctx_t *ctx) {
    ec_gtable_init();
    pe_clone(&ctx->gpoints[0], &G1);
    ec_jacobi_dbl(&ctx->gpoints[1], &ctx->gpoints[0]);
    for (u64 i = 2; i < GROUP_INV_SIZE; ++i) {
        ec_jacobi_add(&ctx->gpoints[i], &ctx->gpoints[i - 1], &G1);
    }
    ec_jacobi_grprdc(ctx->gpoints, GROUP_INV_SIZE);

    if (ctx->random_mode) {
        ctx->job_size = RANDOM_JUMP_INTERVAL;
    } else {
        ctx->job_size = MAX_JOB_SIZE;
        mpz_t range_diff;
        mpz_init(range_diff);
        mpz_sub(range_diff, ctx->gmp_range_e, ctx->gmp_range_s);
        if (mpz_cmp_ui(range_diff, ctx->job_size) < 0) {
            if (mpz_fits_ulong_p(range_diff)) {
                ctx->job_size = mpz_get_ui(range_diff) + 1;
            }
        }
        mpz_clear(range_diff);
    }
    
    for (size_t i = 0; i < ctx->threads_count; ++i) {
        pthread_create(&ctx->threads[i], NULL, cmd_puzzle_worker, ctx);
    }

    while (true) {
        ctx_print_status(ctx); 

        if (!ctx->random_mode) {
            bool all_jobs_assigned = false;
            pthread_mutex_lock(&ctx->lock);
            if (mpz_cmp(ctx->gmp_range_s, ctx->gmp_range_e) >= 0) {
                all_jobs_assigned = true;
            }
            pthread_mutex_unlock(&ctx->lock);

            if (all_jobs_assigned) {
                break;
            }
        }
        
        usleep(10000);
    }

    for (size_t i = 0; i < ctx->threads_count; ++i) {
        pthread_join(ctx->threads[i], NULL);
    }
    
    ctx_print_status(ctx);
    printf("\n");
    
    return 0;
}
// Reimplementation and modification ：https://github.com/8891689
void *cmd_brain_worker(void *arg) {
    ctx_t *ctx = (ctx_t *)arg;
    Sha256Avx8_C_Handle *sha_hasher = sha256_avx8_create();
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
        
        atomic_fetch_add(&ctx->k_checked, job->count);
        if (found_in_job > 0) {
            atomic_fetch_add(&ctx->k_found, found_in_job);
        }
        
        if(job->count > 0) ctx_print_status(ctx);
    }
    if (job != NULL) free(job);
    sha256_avx8_destroy(sha_hasher);
    return NULL;
}

int cmd_brain(ctx_t *ctx) {
  ec_gtable_init();
  for (size_t i = 0; i < ctx->threads_count; ++i) {
    pthread_create(&ctx->threads[i], NULL, cmd_brain_worker, ctx);
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

void arg_parse_range(ctx_t *ctx, args_t *args) {
    char *raw = arg_str(args, "-r");
    if (!raw) {
        fprintf(stderr, "Error: 'puzzle' mode requires a range specified with -r (e.g., -r 1:FFFF)\n");
        exit(1);
    }
    if (set_range(raw, ctx->gmp_range_s, ctx->gmp_range_e) != 0) exit(1);
    if (mpz_cmp(ctx->gmp_range_s, ctx->gmp_range_e) >= 0) {
        fprintf(stderr, "invalid search range, start must be less than end.\n");
        exit(1);
    }
}

void usage(const char *name) {
    printf("Usage: %s -m <mode> [options]\n", name);
    printf("v%s, developed by 8891689\n", VERSION);
    printf("\nModes (-m):\n");
    printf("  puzzle          Puzzle solving mode. Searches for keys in a given range.\n");
    printf("  brain           Brainwallet mode. Reads keys or passphrases from standard input.\n");
    printf("  bloom           Generate a bloom filter from stdin.\n");
    printf("\nCommon Options:\n");
    printf("  -b <file>       Bloom filter file for quick checks.\n");
    printf("  -f <file>       Hash list file for final confirmation.\n");
    printf("  -o <file>       Output file for found keys (default: stdout).\n");
    printf("  -t <threads>    Number of threads to use (default: 1).\n");
    printf("  -a <addr_type>  Address type: 'c' (compressed), 'u' (uncompressed), 'cu' (both). Default: c.\n");
    printf("  -q              Quiet mode (no status updates to stdout).\n");
    printf("\nPuzzle Mode Options:\n");
    printf("  -r <start:end>  Search range in hexadecimal format (required for puzzle mode).\n");
    printf("  -R              Enable random mode. Jumps to a new random key every ~100 million checks.\n");
    printf("\nBrain Mode Options:\n");
    printf("  -sha            Treat stdin lines as passphrases, hash them with SHA256 to get private keys.\n");
}

void init(ctx_t *ctx, args_t *args) {
    if (args->argc > 1 && strcmp(args->argv[1], "bloom") == 0) { 
        blf_gen(args); exit(0); 
    }
    char *mode_str_check = arg_str(args, "-m");
    if (mode_str_check && strcmp(mode_str_check, "bloom") == 0) {
        blf_gen(args); exit(0);
    }

    ctx->mode = MODE_NIL;
    char* mode_str = arg_str(args, "-m");
    if (mode_str) {
        if (strcmp(mode_str, "puzzle") == 0) ctx->mode = MODE_PUZZLE;
        else if (strcmp(mode_str, "brain") == 0) ctx->mode = MODE_BRAIN;
    }
    
    if (ctx->mode == MODE_NIL) {
        usage(args->argv[0]); exit(0);
    }
    
    char *bloom_path = arg_str(args, "-b");
    if (bloom_path) load_bloom(ctx, bloom_path);
    char *hash_path = arg_str(args, "-f");
    if (hash_path) load_hash_list(ctx, hash_path);
    
    ctx->quiet = args_bool(args, "-q");
    char *outfile = arg_str(args, "-o");
    if (outfile) ctx->outfile = fopen(outfile, "a");
    if (outfile == NULL && ctx->quiet) { fprintf(stderr, "Quiet mode requires an output file (-o).\n"); exit(1); }
    
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
    atomic_init(&ctx->k_checked, 0); 
    atomic_init(&ctx->k_found, 0);  
    ctx->stime = tsnow();
    // Reimplementation and modification ：https://github.com/8891689
    mpz_init(ctx->gmp_range_s);
    mpz_init(ctx->gmp_range_e);
    mpz_init(ctx->gmp_curve_n);
    mpz_set_str(ctx->gmp_curve_n, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBD25E8CD0364141", 16);

    if (ctx->mode == MODE_PUZZLE) {
        ctx->random_mode = args_bool(args, "-R");
        arg_parse_range(ctx, args);
    }
    if (ctx->mode == MODE_BRAIN) {
        queue_init(&ctx->queue, ctx->threads_count * 3);
        ctx->raw_text = args_bool(args, "-sha");
    }

    printf("[+] Version %s , developed by 8891689\n", VERSION);
    printf("[+] Mode %s\n", ctx->mode == MODE_PUZZLE ? "puzzle" : "brain");
    if (ctx->check_addr33 && ctx->check_addr65) {
        printf("[+] Search compress and uncompress\n");
    } else if (ctx->check_addr33) {
        printf("[+] Search compress only\n");
    } else if (ctx->check_addr65) {
        printf("[+] Search uncompress only\n");
    }
    printf("[+] Thread : %zu\n", ctx->threads_count);

    if (ctx->mode == MODE_PUZZLE && ctx->random_mode) {
        printf("[+] Random mode\n");
        printf("[+] N = 0x%llx\n", RANDOM_JUMP_INTERVAL);
    }
    if (ctx->mode == MODE_PUZZLE) {
        printf("[+] Range \n");
        gmp_printf("[+] -- from : 0x%Zx\n", ctx->gmp_range_s);
        gmp_printf("[+] -- to   : 0x%Zx\n", ctx->gmp_range_e);
    }
    if (ctx->use_bloom || ctx->use_confirm) {
        size_t total_elements = ctx->use_confirm ? ctx->to_find_count : 1;
        double blf_mem = ctx->use_bloom ? (double)(ctx->blf.size * sizeof(u64)) / (1024*1024) : 0.0;
        printf("[+] Allocating memory for %zu elements: %.2f MB\n", total_elements, blf_mem);
        printf("[+] Bloom filter for %zu elements.\n", total_elements);
        double list_mem = ctx->use_confirm ? (double)(ctx->to_find_count * sizeof(h160_t)) / (1024*1024) : 0.0;
        printf("[+] Loading data to the bloomfilter total: %.2f MB\n", list_mem);
        if(ctx->use_confirm) {
            printf("[+] Sorting data ... done! %zu values were loaded and sorted\n", ctx->to_find_count);
        }
    }
}

int main(int argc, const char **argv) {
  setlocale(LC_NUMERIC, "");
  args_t args = {argc, argv};
  ctx_t ctx = {0};
  
  init(&ctx, &args);
  
  if (ctx.mode == MODE_PUZZLE) {
      cmd_puzzle(&ctx);
  }
  
  if (ctx.mode == MODE_BRAIN) {
      cmd_brain(&ctx);
  }
  
  if (ctx.outfile != NULL) fclose(ctx.outfile);
  mpz_clear(ctx.gmp_range_s);
  mpz_clear(ctx.gmp_range_e); 
  mpz_clear(ctx.gmp_curve_n); 
  return 0;
}
