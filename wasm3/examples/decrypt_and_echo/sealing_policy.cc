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

// LIVE_SNIPPET_BLOCK_1_START
#include "third_party/sealedcomputing/wasm3/base.h"
#include "third_party/sealedcomputing/wasm3/examples/decrypt_and_echo/decrypt_and_echo.common.h"

namespace sealed {
namespace decrypt_and_echo {
namespace server {

using ::sealed::wasm::StatusOr;

StatusOr<DecryptAndEchoResponse> DecryptAndEcho(
    const DecryptAndEchoRequest& request) {
  wasm::ByteString raw_ciphertext =
      request.ciphertext.substr(wasm::kTinkPrefixLength);
  SC_ASSIGN_OR_RETURN(
      wasm::SecretByteString plaintext,
      wasm::DecryptWithGroupKey(raw_ciphertext, /*context_info=*/""));
  return DecryptAndEchoResponse{plaintext.string()};
}

}  // namespace server
}  // namespace decrypt_and_echo
}  // namespace sealed

WASM_EXPORT int start() {
  // Do server initialization here: i.e. initializing all server-scoped state.
  // No server-scoped state to initialize yet.

  sealed::decrypt_and_echo::server::RegisterRpcHandlers();
  // Start serving.
  sealed::wasm::Serve();
  return 0;
}
// LIVE_SNIPPET_BLOCK_1_END
