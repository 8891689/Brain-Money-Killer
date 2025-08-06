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
#pragma once
#include <stdalign.h>

// https://github.com/8891689
#if !defined(swap32)
#if __has_builtin(__builtin_bswap32)
#define swap32(x) __builtin_bswap32(x)
#else
#define swap32(x) ((x) << 24) | (((x) << 8) & 0x00ff0000) | (((x) >> 8) & 0x0000ff00) | ((x) >> 24)
#endif
#endif

#include "ecc.h"
#include "sha256_avx.h"
#include "ripemd160_avx.h"
#include "addr.h"

typedef u32 h160_t[5];

int compare_160(const void *a, const void *b) {
  const u32 *ua = (const u32 *)a;
  const u32 *ub = (const u32 *)b;
  for (int i = 0; i < 5; i++) {
    if (ua[i] < ub[i]) return -1;
    if (ua[i] > ub[i]) return 1;
  }
  return 0;
}

void print_h160(const h160_t h) {
  for (int i = 0; i < 5; i++) printf("%08x", h[i]);
  printf("\n");
}

void addrs33_avx2_batch(h160_t results[LANE_COUNT], const pe points[LANE_COUNT],
                        Sha256Avx8_C_Handle* sha_hasher, RIPEMD160_MULTI_CTX* ripemd_ctx)
{
    alignas(64) uint8_t input_blocks[LANE_COUNT][64];
    alignas(32) uint8_t sha256_digests[LANE_COUNT][32];

    for (int i = 0; i < LANE_COUNT; ++i) {
        uint8_t msg[33];
        msg[0] = points[i].y[0] & 1 ? 0x03 : 0x02;
        for (int j = 0; j < 4; j++) {
            u64 val = points[i].x[3 - j];
            msg[1 + j * 8] = val >> 56; msg[2 + j * 8] = val >> 48;
            msg[3 + j * 8] = val >> 40; msg[4 + j * 8] = val >> 32;
            msg[5 + j * 8] = val >> 24; msg[6 + j * 8] = val >> 16;
            msg[7 + j * 8] = val >> 8;  msg[8 + j * 8] = val;
        }
        prepare_test_data_block(input_blocks[i], (const char*)msg, 33);
    }
    // https://github.com/8891689
    sha256_avx8_init(sha_hasher);
    sha256_avx8_update_8_blocks(sha_hasher, input_blocks);
    sha256_avx8_get_final_hashes(sha_hasher, sha256_digests);

    ripemd160_multi_init(ripemd_ctx);
    for(int i = 0; i < LANE_COUNT; i++) {
        memcpy(ripemd_ctx->buffer[i], sha256_digests[i], 32);
        ripemd_ctx->buffer_len[i] = 32;
    }
    ripemd160_multi_final(ripemd_ctx, (uint8_t(*)[20])results);

    for (int i = 0; i < LANE_COUNT; ++i) {
        for (int j = 0; j < 5; ++j) {
            results[i][j] = swap32(results[i][j]);
        }
    }
}

void addrs65_avx2_batch(h160_t results[LANE_COUNT], const pe points[LANE_COUNT],
                        Sha256Avx8_C_Handle* sha_hasher, RIPEMD160_MULTI_CTX* ripemd_ctx)
{
    alignas(64) uint8_t blocks1[LANE_COUNT][64];
    alignas(64) uint8_t blocks2[LANE_COUNT][64];
    alignas(32) uint8_t sha256_digests[LANE_COUNT][32];

    for (int i = 0; i < LANE_COUNT; ++i) {
        uint8_t msg[65];
        msg[0] = 0x04;
        for (int j = 0; j < 4; j++) {
            u64 val = points[i].x[3 - j];
            msg[1 + j * 8] = val >> 56; msg[2 + j * 8] = val >> 48;
            msg[3 + j * 8] = val >> 40; msg[4 + j * 8] = val >> 32;
            msg[5 + j * 8] = val >> 24; msg[6 + j * 8] = val >> 16;
            msg[7 + j * 8] = val >> 8;  msg[8 + j * 8] = val;
        }
        for (int j = 0; j < 4; j++) {
            u64 val = points[i].y[3 - j];
            msg[33 + j * 8] = val >> 56; msg[34 + j * 8] = val >> 48;
            msg[35 + j * 8] = val >> 40; msg[36 + j * 8] = val >> 32;
            msg[37 + j * 8] = val >> 24; msg[38 + j * 8] = val >> 16;
            msg[39 + j * 8] = val >> 8;  msg[40 + j * 8] = val;
        }

        memcpy(blocks1[i], msg, 64);
        memset(blocks2[i], 0, 64);
        blocks2[i][0] = msg[64];
        blocks2[i][1] = 0x80;
        uint64_t total_bits = 65 * 8;
        for (int j = 0; j < 8; j++) {
            blocks2[i][63 - j] = (total_bits >> (j * 8)) & 0xFF;
        }
    }
    // https://github.com/8891689
    sha256_avx8_init(sha_hasher);
    sha256_avx8_update_8_blocks(sha_hasher, blocks1);
    sha256_avx8_update_8_blocks(sha_hasher, blocks2);
    sha256_avx8_get_final_hashes(sha_hasher, sha256_digests);

    ripemd160_multi_init(ripemd_ctx);
    for(int i = 0; i < LANE_COUNT; i++) {
        memcpy(ripemd_ctx->buffer[i], sha256_digests[i], 32);
        ripemd_ctx->buffer_len[i] = 32;
    }
    ripemd160_multi_final(ripemd_ctx, (uint8_t(*)[20])results);

    for (int i = 0; i < LANE_COUNT; ++i) {
        for (int j = 0; j < 5; ++j) {
            results[i][j] = swap32(results[i][j]);
        }
    }
}
