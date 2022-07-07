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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_UEFI_CRYPTO_CPU_ID_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_UEFI_CRYPTO_CPU_ID_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// This is used by BoringSSL to cache CPU_ID flags and some additional
// BoringSSL-specific flags.  They are used in assembly code to branch to code
// using instructions supported by the CPU, such as SHA extensions and AVX2.
extern uint32_t OPENSSL_ia32cap_P[4];

#ifdef __cplusplus
}  // extern C
#endif

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_UEFI_CRYPTO_CPU_ID_H_
