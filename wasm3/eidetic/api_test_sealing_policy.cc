//  Copyright 2021 Google LLC.
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
#include "third_party/sealedcomputing/wasm3/eidetic/api.h"
#include "third_party/sealedcomputing/wasm3/eidetic/api_test.common.h"
#include "third_party/sealedcomputing/wasm3/enforcer/provisioned_state.h"
#include "third_party/sealedcomputing/wasm3/enforcer/server.h"
#include "third_party/sealedcomputing/wasm3/status.h"
#include "third_party/sealedcomputing/wasm3/statusor.h"

::sealed::eidetic::EideticQuorum* global_eidetic_quorum = nullptr;

WASM_EXPORT int start() {
  global_eidetic_quorum = new ::sealed::eidetic::EideticQuorum();
  sealed::eidetic::server::RegisterRpcHandlers();
  sealed::wasm::Serve();
  return 0;
}

namespace sealed {
namespace eidetic {
namespace server {

namespace {

using ::sealed::wasm::ProvisionedState;
using ::sealed::wasm::Status;
using ::sealed::wasm::StatusOr;

StatusOr<const ProvisionedState*> GetProvisionedState() {
  SC_CHECK(!!sealed::wasm::global_server);
  ProvisionedState* provisioned_state =
      sealed::wasm::global_server->GetProvisionedState();
  if (provisioned_state == nullptr) {
    return Status(wasm::kFailedPrecondition, "no provisioned state found");
  }
  return provisioned_state;
}

}  // namespace

StatusOr<TestReadResponse> TestRead(const TestReadRequest& request) {
  SC_ASSIGN_OR_RETURN(std::string state,
                      global_eidetic_quorum->ReadConsensus());
  TestReadResponse response;
  response.state = state;
  return response;
}

StatusOr<TestWriteResponse> TestWrite(const TestWriteRequest& request) {
  SC_RETURN_IF_ERROR(global_eidetic_quorum->WriteConsensus(request.state));
  return TestWriteResponse();
}

StatusOr<GetMacKeyResponse> GetMacKey(const GetMacKeyRequest& request) {
  SC_ASSIGN_OR_RETURN(auto provisioned_state, GetProvisionedState());
  GetMacKeyResponse response;
  response.mac_key = provisioned_state->GetTaskHmacKey();
  return response;
}

StatusOr<TestHealResponse> TestHeal(const TestHealRequest& request) {
  SC_ASSIGN_OR_RETURN(std::string state,
                      global_eidetic_quorum->HealConsensus());
  TestHealResponse response;
  response.state = state;
  return response;
}

}  // namespace server
}  // namespace eidetic
}  // namespace sealed
