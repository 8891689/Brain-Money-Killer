/* sha256_avx.c */
/* Apache License, Version 2.0
   Copyright [2025] [8891689]

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
   Author: 8891689 (https://github.com/8891689)
*/
#include "sha256_avx.h" 
#include <immintrin.h>  
#include <stdint.h>
#include <string.h>    
#include <stdlib.h>    
#include <stdalign.h>  
#include <stdio.h>

#if defined(__GLIBC__) || defined(__APPLE__) || defined(__FreeBSD__)
#include <strings.h>
#else
static inline void explicit_bzero(void *s, size_t n) { volatile unsigned char *p = s; while (n--) *p++ = 0; }
#endif

// --- Internal structure definition ---
typedef struct { alignas(64) __m256i state[8]; } SHA256_CTX_AVX8;
struct Sha256Avx8_C_Handle { SHA256_CTX_AVX8 ctx; };

// --- Alternative implementations of compiler built-in functions ---
#ifndef __builtin_bswap32
#define __builtin_bswap32(x) ((((x) & 0xff000000u) >> 24) | (((x) & 0x00ff0000u) >> 8) | (((x) & 0x0000ff00u) << 8) | (((x) & 0x000000ffu) << 24))
#endif
#ifndef __builtin_bswap64
#define __builtin_bswap64(x) (((x) >> 56) | (((x) & 0x00ff000000000000ull) >> 40) | (((x) & 0x0000ff0000000000ull) >> 24) | (((x) & 0x000000ff00000000ull) >> 8) | (((x) & 0x00000000ff000000ull) << 8) | (((x) & 0x0000000000ff0000ull) << 24) | (((x) & 0x000000000000ff00ull) << 40) | ((x) << 56))
#endif

#define SHA256_H0 0x6a09e667
#define SHA256_H1 0xbb67ae85
#define SHA256_H2 0x3c6ef372
#define SHA256_H3 0xa54ff53a
#define SHA256_H4 0x510e527f
#define SHA256_H5 0x9b05688c
#define SHA256_H6 0x1f83d9ab
#define SHA256_H7 0x5be0cd19

static const uint32_t k_const[64] __attribute__((aligned(64))) = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define BSWAP_MASK _mm256_set_epi32(0x0c0d0e0f, 0x08090a0b, 0x04050607, 0x00010203, 0x0c0d0e0f, 0x08090a0b, 0x04050607, 0x00010203)
#define CH(x, y, z)  _mm256_xor_si256(_mm256_and_si256(x, y), _mm256_andnot_si256(x, z))
#define MAJ(x, y, z) _mm256_xor_si256(_mm256_and_si256(x, y), _mm256_xor_si256(_mm256_and_si256(x, z), _mm256_and_si256(y, z)))
#define ROR(x, n) _mm256_or_si256(_mm256_srli_epi32(x, n), _mm256_slli_epi32(x, 32 - n))
#define SIGMA0(x) (_mm256_xor_si256(ROR(x, 2),  _mm256_xor_si256(ROR(x, 13), ROR(x, 22))))
#define SIGMA1(x) (_mm256_xor_si256(ROR(x, 6),  _mm256_xor_si256(ROR(x, 11), ROR(x, 25))))
#define sigma0(x) (_mm256_xor_si256(ROR(x, 7),  _mm256_xor_si256(ROR(x, 18), _mm256_srli_epi32(x, 3))))
#define sigma1(x) (_mm256_xor_si256(ROR(x, 17), _mm256_xor_si256(ROR(x, 19), _mm256_srli_epi32(x, 10))))

static inline void transpose8x8_epi32(__m256i *rows) {
    __m256i temp[8];
    temp[0] = _mm256_unpacklo_epi32(rows[0], rows[1]); temp[1] = _mm256_unpackhi_epi32(rows[0], rows[1]);
    temp[2] = _mm256_unpacklo_epi32(rows[2], rows[3]); temp[3] = _mm256_unpackhi_epi32(rows[2], rows[3]);
    temp[4] = _mm256_unpacklo_epi32(rows[4], rows[5]); temp[5] = _mm256_unpackhi_epi32(rows[4], rows[5]);
    temp[6] = _mm256_unpacklo_epi32(rows[6], rows[7]); temp[7] = _mm256_unpackhi_epi32(rows[6], rows[7]);
    rows[0] = _mm256_unpacklo_epi64(temp[0], temp[2]); rows[1] = _mm256_unpackhi_epi64(temp[0], temp[2]);
    rows[2] = _mm256_unpacklo_epi64(temp[1], temp[3]); rows[3] = _mm256_unpackhi_epi64(temp[1], temp[3]);
    rows[4] = _mm256_unpacklo_epi64(temp[4], temp[6]); rows[5] = _mm256_unpackhi_epi64(temp[4], temp[6]);
    rows[6] = _mm256_unpacklo_epi64(temp[5], temp[7]); rows[7] = _mm256_unpackhi_epi64(temp[5], temp[7]);
    temp[0] = _mm256_permute2x128_si256(rows[0], rows[4], 0x20); temp[1] = _mm256_permute2x128_si256(rows[1], rows[5], 0x20);
    temp[2] = _mm256_permute2x128_si256(rows[2], rows[6], 0x20); temp[3] = _mm256_permute2x128_si256(rows[3], rows[7], 0x20);
    temp[4] = _mm256_permute2x128_si256(rows[0], rows[4], 0x31); temp[5] = _mm256_permute2x128_si256(rows[1], rows[5], 0x31);
    temp[6] = _mm256_permute2x128_si256(rows[2], rows[6], 0x31); temp[7] = _mm256_permute2x128_si256(rows[3], rows[7], 0x31);
    memcpy(rows, temp, sizeof(temp));
}

static void internal_init_ctx(SHA256_CTX_AVX8 *ctx) {
    ctx->state[0] = _mm256_set1_epi32(SHA256_H0); ctx->state[1] = _mm256_set1_epi32(SHA256_H1);
    ctx->state[2] = _mm256_set1_epi32(SHA256_H2); ctx->state[3] = _mm256_set1_epi32(SHA256_H3);
    ctx->state[4] = _mm256_set1_epi32(SHA256_H4); ctx->state[5] = _mm256_set1_epi32(SHA256_H5);
    ctx->state[6] = _mm256_set1_epi32(SHA256_H6); ctx->state[7] = _mm256_set1_epi32(SHA256_H7);
}

// Core expansion logic
void sha256_transform_avx8(SHA256_CTX_AVX8 *ctx, const uint8_t input_data_8blocks[8][64]) {
    alignas(64) __m256i W[64];
    const __m256i bswap_mask = BSWAP_MASK;
    
    // --- Message block preprocessing ---
    __m256i block_data[8];
    for (int i = 0; i < 8; i++) {
        // [Optimization] Use aligned loading
        block_data[i] = _mm256_load_si256((const __m256i*)input_data_8blocks[i]);
        block_data[i] = _mm256_shuffle_epi8(block_data[i], bswap_mask);
    }
    transpose8x8_epi32(block_data);
    for (int i = 0; i < 8; i++) W[i] = block_data[i];
    
    for (int i = 0; i < 8; i++) {
        block_data[i] = _mm256_load_si256((const __m256i*)(input_data_8blocks[i] + 32));
        block_data[i] = _mm256_shuffle_epi8(block_data[i], bswap_mask);
    }
    transpose8x8_epi32(block_data);
    for (int i = 0; i < 8; i++) W[i + 8] = block_data[i];

    // --- Message Extension ---
    for (int i = 16; i < 64; ++i) {
        __m256i s1 = sigma1(W[i-2]);
        __m256i s0 = sigma0(W[i-15]);
        W[i] = _mm256_add_epi32(s1, _mm256_add_epi32(W[i-7], _mm256_add_epi32(W[i-16], s0)));
    }

    // --- Main Loop ---
    __m256i a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    __m256i e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];
    
    // Preload k and W for the first 4 rounds
    __m256i k0 = _mm256_set1_epi32(k_const[0]);
    __m256i k1 = _mm256_set1_epi32(k_const[1]);
    __m256i k2 = _mm256_set1_epi32(k_const[2]);
    __m256i k3 = _mm256_set1_epi32(k_const[3]);
   
    __m256i w0 = W[0];
    __m256i w1 = W[1];
    __m256i w2 = W[2];
    __m256i w3 = W[3];
    
    for (int i = 0; i < 64; i += 4) {
        // Calculate T1 and T2
        __m256i t1_0 = _mm256_add_epi32(h, _mm256_add_epi32(SIGMA1(e), _mm256_add_epi32(CH(e, f, g), _mm256_add_epi32(k0, w0))));
        __m256i t2_0 = _mm256_add_epi32(SIGMA0(a), MAJ(a, b, c));
        // Update Status
        h = g; g = f; f = e; e = _mm256_add_epi32(d, t1_0); d = c; c = b; b = a; a = _mm256_add_epi32(t1_0, t2_0);
        // Preload k and W for step 0 of the next big round
        if (i + 4 < 64) { k0 = _mm256_set1_epi32(k_const[i+4]); w0 = W[i+4]; }
        
        __m256i t1_1 = _mm256_add_epi32(h, _mm256_add_epi32(SIGMA1(e), _mm256_add_epi32(CH(e, f, g), _mm256_add_epi32(k1, w1))));
        __m256i t2_1 = _mm256_add_epi32(SIGMA0(a), MAJ(a, b, c));
        h = g; g = f; f = e; e = _mm256_add_epi32(d, t1_1); d = c; c = b; b = a; a = _mm256_add_epi32(t1_1, t2_1);
        if (i + 5 < 64) { k1 = _mm256_set1_epi32(k_const[i+5]); w1 = W[i+5]; }
        
        __m256i t1_2 = _mm256_add_epi32(h, _mm256_add_epi32(SIGMA1(e), _mm256_add_epi32(CH(e, f, g), _mm256_add_epi32(k2, w2))));
        __m256i t2_2 = _mm256_add_epi32(SIGMA0(a), MAJ(a, b, c));
        h = g; g = f; f = e; e = _mm256_add_epi32(d, t1_2); d = c; c = b; b = a; a = _mm256_add_epi32(t1_2, t2_2);
        if (i + 6 < 64) { k2 = _mm256_set1_epi32(k_const[i+6]); w2 = W[i+6]; }
        
        __m256i t1_3 = _mm256_add_epi32(h, _mm256_add_epi32(SIGMA1(e), _mm256_add_epi32(CH(e, f, g), _mm256_add_epi32(k3, w3))));
        __m256i t2_3 = _mm256_add_epi32(SIGMA0(a), MAJ(a, b, c));
        h = g; g = f; f = e; e = _mm256_add_epi32(d, t1_3); d = c; c = b; b = a; a = _mm256_add_epi32(t1_3, t2_3);
        if (i + 7 < 64) { k3 = _mm256_set1_epi32(k_const[i+7]); w3 = W[i+7]; }
    }

    // --- Update final status ---
    ctx->state[0] = _mm256_add_epi32(ctx->state[0], a); ctx->state[1] = _mm256_add_epi32(ctx->state[1], b);
    ctx->state[2] = _mm256_add_epi32(ctx->state[2], c); ctx->state[3] = _mm256_add_epi32(ctx->state[3], d);
    ctx->state[4] = _mm256_add_epi32(ctx->state[4], e); ctx->state[5] = _mm256_add_epi32(ctx->state[5], f);
    ctx->state[6] = _mm256_add_epi32(ctx->state[6], g); ctx->state[7] = _mm256_add_epi32(ctx->state[7], h);
}

// --- Implementation of public interface functions ---
Sha256Avx8_C_Handle* sha256_avx8_create() {
    Sha256Avx8_C_Handle* handle = (Sha256Avx8_C_Handle*)aligned_alloc(64, sizeof(Sha256Avx8_C_Handle));
    if (!handle) return NULL;
    internal_init_ctx(&handle->ctx);
    return handle;
}
void sha256_avx8_destroy(Sha256Avx8_C_Handle* handle) {
    if (handle) {
        explicit_bzero(handle, sizeof(Sha256Avx8_C_Handle));
        free(handle);
    }
}
void sha256_avx8_init(Sha256Avx8_C_Handle* handle) {
    if (!handle) return;
    internal_init_ctx(&handle->ctx);
}
void sha256_avx8_update_8_blocks(Sha256Avx8_C_Handle* handle, const uint8_t input_blocks[8][64]) {
    if (!handle || !input_blocks) return;
    sha256_transform_avx8(&handle->ctx, input_blocks);
}


void sha256_avx8_get_final_hashes(Sha256Avx8_C_Handle* handle, uint8_t hashes_out[8][32]) {
    if (!handle || !hashes_out) return;
    const __m256i bswap_final_mask = _mm256_setr_epi8(
        3, 2, 1, 0,   7, 6, 5, 4,   11, 10, 9, 8,   15, 14, 13, 12,
        3, 2, 1, 0,   7, 6, 5, 4,   11, 10, 9, 8,   15, 14, 13, 12
    );
    alignas(64) __m256i transposed_state[8];
    memcpy(transposed_state, handle->ctx.state, sizeof(transposed_state));
    transpose8x8_epi32(transposed_state);
    for (int i = 0; i < 8; ++i) {
        __m256i final_hash_vec = transposed_state[i];
        final_hash_vec = _mm256_shuffle_epi8(final_hash_vec, bswap_final_mask);
        _mm256_storeu_si256((__m256i*)hashes_out[i], final_hash_vec);
    }
}

void prepare_test_data_block(uint8_t block[64], const char* message, size_t message_len_bytes) {
    if (message_len_bytes >= 56) {
        fprintf(stderr, "Error: prepare_test_data_block only supports messages shorter than 56 bytes. Got %zu.\n", message_len_bytes);
        exit(EXIT_FAILURE);
    }
    memset(block, 0, 64);
    if (message && message_len_bytes > 0) {
        memcpy(block, message, message_len_bytes);
    }
    block[message_len_bytes] = 0x80;
    uint64_t bit_length = __builtin_bswap64(message_len_bytes * 8);
    memcpy(block + 56, &bit_length, 8);
}
