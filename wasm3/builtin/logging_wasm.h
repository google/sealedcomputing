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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_BUILTIN_LOGGING_WASM_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_BUILTIN_LOGGING_WASM_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

// This logs an error message, and reboots the interpreter.
void biPanic(const void* filename, int32_t line, const void* text);

// Send a log message to the host, which should include it in their own log.
void biSendLogRpc(int32_t level, const void* filename, int32_t line,
                  const void* text);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_BUILTIN_LOGGING_WASM_H_
