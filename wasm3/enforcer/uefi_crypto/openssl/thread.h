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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_UEFI_CRYPTO_OPENSSL_THREAD_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_UEFI_CRYPTO_OPENSSL_THREAD_H_

// This is a dummy implementation of BoringSSL's thread.h, to keep it from
// getting sucked in along with all of its dependencies.

#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

typedef uint32_t CRYPTO_refcount_t;
typedef uint32_t CRYPTO_MUTEX;

#if defined(__cplusplus)
}  // extern C
#endif

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_UEFI_CRYPTO_OPENSSL_THREAD_H_
