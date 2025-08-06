/* sha256_avx.h */
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

#ifndef SHA256_AVX_H
#define SHA256_AVX_H

#include <stdint.h>
#include <stddef.h> 

// Compile-time check to ensure AVX2 is enabled
#if !defined(__AVX2__)
#error "This implementation requires AVX2 support. Please compile with -mavx2."
#endif

// --- C++ compatibility ---
#ifdef __cplusplus
extern "C" {
#endif

// --- Opaque pointer definition ---
struct Sha256Avx8_C_Handle; 
typedef struct Sha256Avx8_C_Handle Sha256Avx8_C_Handle;

// --- Public interface function ---

/**
* @brief Creates and initializes a new SHA256 AVX8 processor handle.
* @return Returns a valid handle on success, or NULL if memory allocation fails.
*/
Sha256Avx8_C_Handle* sha256_avx8_create();

/**
* @brief Destroys a handle and safely frees associated memory (this will clear the memory).
* @param handle The handle created by sha256_avx8_create(). If NULL, no action is performed.
*/
void sha256_avx8_destroy(Sha256Avx8_C_Handle* handle);

/**
* @brief Reinitializes the hash state, allowing the handle to be reused for new computations.
* @param handle A valid handle. If NULL, no action is performed.
*/
void sha256_avx8_init(Sha256Avx8_C_Handle* handle);

/**
* @brief Process eight 64-byte data blocks in parallel.
* @param handle A valid handle.
* @param input_blocks An array of eight 64-byte data blocks. They must be 64-byte aligned.
* If handle or input_blocks is NULL, no action is performed.
*/
void sha256_avx8_update_8_blocks(Sha256Avx8_C_Handle* handle, const uint8_t input_blocks[8][64]);

/**
* @brief Extracts the 8 final hash digests from the internal state.
* @param handle A valid handle.
* @param hashes_out An output array to store the 8 32-byte hash results.
* If handle or hashes_out is NULL, no action is performed.
*/
void sha256_avx8_get_final_hashes(Sha256Avx8_C_Handle* handle, uint8_t hashes_out[8][32]);


// --- Test helper functions ---

/**
* @brief Prepares a single data block that conforms to the SHA-256 padding rules.
* This function is primarily used to test single-block messages.
* @param block Output buffer, 64 bytes in size.
* @param message Input message string.
* @param message_len_bytes Message length (bytes). The length must be less than 56.
*/
void prepare_test_data_block(uint8_t block[64], const char* message, size_t message_len_bytes);


#ifdef __cplusplus
} // extern "C"
#endif

#endif // SHA256_AVX_H
