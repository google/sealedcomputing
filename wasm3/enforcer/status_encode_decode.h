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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_STATUS_ENCODE_DECODE_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_STATUS_ENCODE_DECODE_H_

#include "third_party/sealedcomputing/wasm3/status.h"

namespace sealed {
namespace wasm {

// Returns an encoding of a given `status`.
std::string EncodeStatus(const Status& status);

// Returns a non-OK status iff there is any error decoding `encoded_status` into
// `status`.
Status DecodeStatus(const std::string& encoded_status, Status* status);

}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_STATUS_ENCODE_DECODE_H_
