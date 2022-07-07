//  Copyright 2022 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// These stubs are needed to link BoringSSL's AES code without the
// "No-hardware" implementation, which unfortunately for us, actually uses SSE2,
// and Intel intrinsics, which are not supported by Nanolibc.

#include <stdint.h>
#include <stdio.h>

#include "third_party/openssl/boringssl/src/crypto/fipsmodule/modes/internal.h"
#include "third_party/openssl/boringssl/src/crypto/internal.h"
#include "third_party/openssl/boringssl/src/include/openssl/aes.h"

int aes_nohw_set_encrypt_key(const uint8_t *key, unsigned bits,
                             AES_KEY *aeskey) {
  printf("Executing AES no-hardware stub!\n");
  abort();
  return 0;
}

int aes_nohw_set_decrypt_key(const uint8_t *key, unsigned bits,
                             AES_KEY *aeskey) {
  printf("Executing AES no-hardware stub!\n");
  abort();
  return 0;
}

void aes_nohw_encrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key) {
  printf("Executing AES no-hardware stub!\n");
  abort();
}

void aes_nohw_decrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key) {
  printf("Executing AES no-hardware stub!\n");
  abort();
}

void aes_nohw_ctr32_encrypt_blocks(const uint8_t *in, uint8_t *out,
                                   size_t blocks, const AES_KEY *key,
                                   const uint8_t ivec[16]) {
  printf("Executing AES no-hardware stub!\n");
  abort();
}

void aes_nohw_cbc_encrypt(const uint8_t *in, uint8_t *out, size_t len,
                          const AES_KEY *key, uint8_t *ivec, const int enc) {
  printf("Executing AES no-hardware stub!\n");
  abort();
}

void gcm_init_nohw(u128 Htable[16], const uint64_t H[2]) {
  printf("Executing AES no-hardware stub!\n");
  abort();
}

void gcm_gmult_nohw(uint64_t Xi[2], const u128 Htable[16]) {
  printf("Executing AES no-hardware stub!\n");
  abort();
}

void gcm_ghash_nohw(uint64_t Xi[2], const u128 Htable[16], const uint8_t *inp,
                    size_t len) {
  printf("Executing AES no-hardware stub!\n");
  abort();
}
