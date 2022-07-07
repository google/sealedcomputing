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

#include <string>

#include "third_party/sealedcomputing/wasm3/base.h"
#include "third_party/sealedcomputing/wasm3/builtin/builtin_wasm.h"
#include "third_party/sealedcomputing/wasm3/logging.h"
#include "third_party/sealedcomputing/wasm3/status.h"
#include "third_party/sealedcomputing/wasm3/tests/serve_quote_proto.h"

extern "C" int start() {
  sealed::wasm::Serve();
  return 0;
}

namespace sealed::serve_quote::server {

sealed::wasm::StatusOr<ServeQuoteResponse> ServeQuote(
    const std::string& challenge) {
  std::string signature, report;
  sealed::wasm::Status status =
      sealed::wasm::Quote(challenge, &report, &signature);
  if (!status) {
    return status;
  } else if (!sealed::wasm::VerifyQuote(challenge, report, signature)) {
    return wasm::Status(wasm::kInternal, "signature verification failed");
  }
  return ServeQuoteResponse{report, signature};
}

}  // namespace sealed::serve_quote::server

extern "C" int WASM_EXPORT ServePanic_RPC(int32_t request_length,
                                          int32_t request_secret_length) {
  SC_PANIC() << "This error is expected.";
  return 1;
}
