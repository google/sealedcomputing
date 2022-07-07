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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_UEFI_CRYPTO_TEST_FAKES_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_UEFI_CRYPTO_TEST_FAKES_H_

// Provide primitives for logging for tests.

#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

// Print the filename, line, and text, and call abort.
void biPanic(const void* filename, int32_t line, const void* text);

// Send a log message to the host, which should include it in their own log.
void biSendLogRpc(int32_t level, const void* filename, int32_t line,
                  const void* text);

// Generates pseudo-random bytes for test purposes.  The prng is seeded the same
// way every time to reduce flaky tests.
//
// WARNING: This is not a secure way to generate secrets!  This is a test fake,
// and should never be linked into production code.
void biRandBytes(void* buf, int32_t len);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_UEFI_CRYPTO_TEST_FAKES_H_
