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
#include <string>

#include "third_party/sealedcomputing/wasm3/examples/echo/echo.common.h"
#include "third_party/sealedcomputing/wasm3/statusor.h"

namespace sealed {
namespace echo {
namespace server {

using ::sealed::wasm::StatusOr;

StatusOr<EchoResponse> Echo(const EchoRequest& request) {
  return EchoResponse{request.request};
}

}  // namespace server
}  // namespace echo
}  // namespace sealed
// LIVE_SNIPPET_BLOCK_1_END

// LIVE_SNIPPET_BLOCK_2_START
WASM_EXPORT int start() {
  // Do server initialization here: i.e. initializing all server-scoped state.
  // No server-scoped state to initialize yet.

  sealed::echo::server::RegisterRpcHandlers();
  // Start serving.
  sealed::wasm::Serve();
  return 0;
}
// LIVE_SNIPPET_BLOCK_2_END
