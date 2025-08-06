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
#ifndef RIPEMD160_avx_H
#define RIPEMD160_avx_H

#include <immintrin.h> 
#include <stdint.h>    
#include <stddef.h>    

#define LANE_COUNT 8
#define BLOCK_SIZE 64
#define DIGEST_SIZE 20

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__GNUC__) || defined(__clang__)
    #define CUSTOM_ALIGNAS(x) __attribute__((aligned(x)))
#elif defined(_MSC_VER)
    #define CUSTOM_ALIGNAS(x) __declspec(align(x))
#elif defined(__cplusplus) && __cplusplus >= 201103L 
    #define CUSTOM_ALIGNAS(x) alignas(x)
#elif !defined(__cplusplus) && defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L 
    #define CUSTOM_ALIGNAS(x) _Alignas(x)
#else
    #define CUSTOM_ALIGNAS(x) 
#endif

typedef struct CUSTOM_ALIGNAS(64) RIPEMD160_MULTI_CTX_TAG {
    __m256i state[5];
    uint64_t total_bits[LANE_COUNT];
    uint8_t buffer[LANE_COUNT][BLOCK_SIZE];
    uint32_t buffer_len[LANE_COUNT];
} RIPEMD160_MULTI_CTX;

void ripemd160_multi_init(RIPEMD160_MULTI_CTX* ctx);
void ripemd160_multi_update_full_blocks(RIPEMD160_MULTI_CTX* ctx, const uint8_t data_blocks[LANE_COUNT][BLOCK_SIZE]);
void ripemd160_multi_final(RIPEMD160_MULTI_CTX* ctx, uint8_t digests[LANE_COUNT][DIGEST_SIZE]);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // RIPEMD160_avx_H
