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

#include "third_party/sealedcomputing/protoc_plugin/tests/service.common.h"
#include "third_party/sealedcomputing/wasm3/statusor.h"

namespace sealed::protoc_plugin::tests::server {

using ::sealed::protoc_plugin::tests::FirstMethodRequest;
using ::sealed::protoc_plugin::tests::FirstMethodResponse;
using ::sealed::protoc_plugin::tests::SecondMethodRequest;
using ::sealed::protoc_plugin::tests::SecondMethodResponse;
using ::sealed::wasm::StatusOr;

StatusOr<FirstMethodResponse> FirstMethod(const FirstMethodRequest& request) {
  FirstMethodResponse response;
  response.response = request.request;
  return response;
}

StatusOr<SecondMethodResponse> SecondMethod(
    const SecondMethodRequest& request) {
  SecondMethodResponse response;
  response.secret_value = request.secret_value;
  return response;
}

}  // namespace sealed::protoc_plugin::tests::server

WASM_EXPORT int start() {
  ::sealed::protoc_plugin::tests::server::RegisterRpcHandlers();
  sealed::wasm::Serve();
  return 0;
}
