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

#include "third_party/sealedcomputing/wasm3/base.h"
#include "third_party/sealedcomputing/wasm3/logging.h"
#include "third_party/sealedcomputing/wasm3/status.h"
#include "third_party/sealedcomputing/wasm3/statusor.h"
#include "third_party/sealedcomputing/wasm3/tests/serve_panic.client.h"
#include "third_party/sealedcomputing/wasm3/tests/serve_panic.common.h"

WASM_EXPORT int start() {
  sealed::wasm::tests::server::RegisterRpcHandlers();
  sealed::wasm::Serve();
  return 0;
}

namespace sealed {
namespace wasm {
namespace tests {
namespace server {

using sealed::wasm::Status;
using sealed::wasm::StatusOr;

StatusOr<ReverseResponse> Reverse(const ReverseRequest& request) {
  ReverseResponse response;
  response.text.resize(request.text.size());
  for (size_t i = 0; i < request.text.size(); ++i) {
    response.text[i] = request.text[request.text.size() - 1 - i];
  }
  return response;
}

StatusOr<ReverseResponse> Error(const ReverseRequest& request) {
  return Status(wasm::kInternal, request.text);
}

StatusOr<ReverseResponse> Panic(const ReverseRequest& request) {
  SC_PANIC() << "This error is expected.";
  return wasm::Status::OkStatus();
}

StatusOr<ReverseResponse> ReverseOuter(const ReverseRequest& request) {
  return client::Reverse(request);
}

StatusOr<ReverseResponse> ErrorOuter(const ReverseRequest& request) {
  return client::Error(request);
}

}  // namespace server
}  // namespace tests
}  // namespace wasm
}  // namespace sealed
