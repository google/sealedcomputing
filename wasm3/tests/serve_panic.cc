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
#include "third_party/sealedcomputing/wasm3/logging.h"
#include "third_party/sealedcomputing/wasm3/status.h"
#include "third_party/sealedcomputing/wasm3/statusor.h"
#include "third_party/sealedcomputing/wasm3/tests/serve_panic_proto.h"

WASM_EXPORT int start() {
  sealed::wasm::Serve();
  return 0;
}

namespace sealed::serve_panic::server {

using sealed::wasm::Status;
using sealed::wasm::StatusOr;

StatusOr<std::string> Reverse(const std::string& text) {
  std::string result = text;
  std::reverse(result.begin(), result.end());
  return result;
}

Status Error(const std::string& errorMessage) {
  return Status(wasm::kInternal, errorMessage);
}

Status Panic(const std::string& errorMessage) {
  SC_PANIC() << "This error is expected.";
  return wasm::Status::OkStatus();
}

StatusOr<std::string> ReverseOuter(const std::string& text) {
  return client::Reverse(text);
}

Status ErrorOuter(const std::string& errorMessage) {
  return client::Error(errorMessage);
}

}  // namespace sealed::serve_panic::server
