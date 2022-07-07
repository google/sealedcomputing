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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_MAIN_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_MAIN_H_

#include <string>
#include <vector>

#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/status.h"

namespace sealed {
namespace wasm {

// Verify that the range from |ptr| to |ptr| + |len| is contained within the
// interpreter's memory.
bool MemCheckRange(const void* ptr, uint32_t len);

// Verify that the C string starting at |ptr| is contained entirely within the
// interpreter's memory.
bool MemCheckCstr(const void* text);

typedef bool*(CallWasmRpcCallback)(const std::string& name,
                                   const std::string& request,
                                   const SecretByteString& request_secret);

// Constructs and initializes the global state associated with the WASM3
// interpreter and parses `in_bytes` as a WASM module.
Status InitWasm(const std::string& in_bytes);

// Calls the `main` function in the WASM module parsed from calling InitWasm.
// Returns non-OK status if InitWasm was not called before.
Status RunWasmMain();

// When compiling as wasm bytecode, CallWasmRpc lives in wasm.cc and calls into
// the bytecode to handle the RPC.  When linked as a stand-alone binary,
// generated code provides this function.  The response is sent by the generated
// RPC code.
bool CallWasmRpc(const std::string& name, const std::string& request,
                 const SecretByteString& request_secret);

// Report an error message, including info saved in the global runtime.
void PrintWasm3Error(const std::string& message);

}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_MAIN_H_
