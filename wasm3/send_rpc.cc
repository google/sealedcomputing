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

#include "third_party/sealedcomputing/wasm3/send_rpc.h"

#include "third_party/sealedcomputing/rpc/encode_decode_lite.h"
#include "third_party/sealedcomputing/wasm3/enforcer/rpc.common.h"
#include "third_party/sealedcomputing/wasm3/enforcer/status_encode_decode.h"
#include "third_party/sealedcomputing/wasm3/status.h"

namespace sealed {
namespace wasm {

Status SendRpc(const std::string& service_name, const std::string& method_name,
               const std::string& request,
               const SecretByteString& request_secret, std::string* response,
               SecretByteString* response_secret, Socket* socket,
               RpcType type) {
  RpcMessage request_message;
  request_message.type = type;
  request_message.service_name = service_name;
  request_message.method_name = method_name;
  request_message.payload = request;
  socket->Send(EncodeRpcMessage(request_message), request_secret);
  ByteString encoded_response_message;
  SC_RETURN_IF_ERROR(socket->Recv(&encoded_response_message, response_secret));
  SC_ASSIGN_OR_RETURN(RpcMessage response_message,
                      DecodeRpcMessage(encoded_response_message));
  if (!response_message.encoded_status.empty()) {
    Status response_status;
    SC_RETURN_IF_ERROR(
        DecodeStatus(response_message.encoded_status, &response_status));
    SC_RETURN_IF_ERROR(response_status);
  }
  *response = response_message.payload;
  return Status::OkStatus();
}

}  // namespace wasm
}  // namespace sealed
