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

#include "third_party/sealedcomputing/wasm3/enforcer/status_encode_decode.h"

#include "third_party/sealedcomputing/rpc/encode_decode_lite.h"
#include "third_party/sealedcomputing/wasm3/status.h"

namespace sealed {
namespace wasm {

std::string EncodeStatus(const Status& status) {
  rpc::Encoder encoder;
  encoder.U8(status.code());
  encoder.String(status.message());
  return encoder.Finish();
}

Status DecodeStatus(const std::string& encoded_status, Status* status) {
  rpc::Decoder decoder(encoded_status);
  uint8_t status_code = 0;
  std::string status_message;
  if (!decoder.U8(&status_code) || !decoder.String(&status_message)) {
    return Status(kInvalidArgument, "error decoding sealed::wasm::Status");
  }
  *status = Status(static_cast<StatusCode>(status_code), status_message);
  return Status::OkStatus();
}

}  // namespace wasm
}  // namespace sealed
