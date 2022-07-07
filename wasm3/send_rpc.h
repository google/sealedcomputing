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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_SEND_RPC_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_SEND_RPC_H_

#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/enforcer/rpc.common.h"
#include "third_party/sealedcomputing/wasm3/socket.h"

namespace sealed {
namespace wasm {

// Sends an RPC request over a given `socket` and receives a response.
// `service_name`, `method_name`, `request` and `type` specify the
// RPC request being made (see rpc.proto for a detailed description).
// `type` must be either `RPC_TYPE_REQUEST` or `RPC_TYPE_SEALET_REQUEST`.
// Returns the `Status` of the RPC and sets `response` and `response_secret` if
// the RPC succeeds.
Status SendRpc(const std::string& service_name, const std::string& method_name,
               const std::string& request,
               const SecretByteString& request_secret, std::string* response,
               SecretByteString* response_secret, Socket* socket,
               RpcType type = RpcType::RPC_TYPE_REQUEST);

}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_SEND_RPC_H_
