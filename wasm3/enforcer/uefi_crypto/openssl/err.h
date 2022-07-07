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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_UEFI_CRYPTO_OPENSSL_ERR_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_UEFI_CRYPTO_OPENSSL_ERR_H_

// This is a dummy implementation of BoringSSL's err.h, to keep it from getting
// sucked in along with all of its dependencies.

#include "third_party/openssl/boringssl/src/include/openssl/base.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OPENSSL_PUT_ERROR(library, reason) \
  ERR_put_error(ERR_LIB_##library, 0, reason, __FILE__, __LINE__)

#define OPENSSL_DECLARE_ERROR_REASON(lib, reason)
#define ERR_GET_REASON(packed_error) 0
#define ERR_GET_LIB(packed_error) 0

enum {
  ERR_LIB_BN,
  ERR_LIB_CIPHER,
  ERR_LIB_CRYPTO,
  ERR_LIB_EC,
  ERR_LIB_EVP,
  ERR_LIB_HMAC,
  ERR_LIB_HKDF,
  ERR_LIB_ECDSA,
  ERR_LIB_DIGEST,
  ERR_LIB_ENGINE,
};

enum {
  ERR_R_BN_LIB,
  ERR_R_EC_LIB,
  ERR_R_INTERNAL_ERROR,
  ERR_R_MALLOC_FAILURE,
  ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED,
  ERR_R_PASSED_NULL_PARAMETER,
  ERR_R_OVERFLOW,
  EVP_R_INVALID_BUFFER_SIZE,
  EVP_R_INVALID_PEER_KEY,
  EVP_R_DECODE_ERROR,
  ERR_R_HMAC_LIB,
};

void ERR_put_error(int library, int unused, int reason, const char *file,
                   unsigned line);

uint32_t ERR_peek_last_error(void);

void ERR_clear_error();

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_UEFI_CRYPTO_OPENSSL_ERR_H_
