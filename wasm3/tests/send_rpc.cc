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

#include <algorithm>

#include "third_party/sealedcomputing/wasm3/base.h"
#include "third_party/sealedcomputing/wasm3/builtin/builtin_wasm.h"
#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/logging.h"

WASM_EXPORT int start() {
  sealed::wasm::Serve();
  return 0;
}

extern "C" int WASM_EXPORT Outer_RPC(int32_t request_length,
                                     int32_t request_secret_length) {
  std::string request(request_length, '\0');
  biGetRequest(request.data(), request_length);

  ::sealed::wasm::ByteString response;
  sealed::wasm::SecretByteString response_secret;
  sealed::wasm::SendRpc("HostService", "Inner", request, /*request_secret=*/"",
                        /*deadline=*/0, &response, &response_secret);
  biSetResponse(response.data(), response.size());
  return 1;
}

extern "C" int WASM_EXPORT SendPanic_RPC(int32_t request_length,
                                         int32_t request_secret_length) {
  SC_PANIC() << "This error is expected.";
  return 1;
}
