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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_WASM_GLOBALS_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_WASM_GLOBALS_H_

#include <string>

#include "third_party/wasm3/source/m3_env.h"
#include "third_party/wasm3/source/wasm3.h"

namespace sealed {
namespace wasm {

// These globals are pointers to plain-old C datatpyes.  No
// constructors/destructors are involved.

// This never changes during the life of the interpreter.  Use it to check
// memory ranges are valid before accessing them.
extern IM3Memory global_mem;
// This is needed to call functions into the interpreter from the server loop.
extern IM3Runtime global_runtime;

}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_WASM_GLOBALS_H_
