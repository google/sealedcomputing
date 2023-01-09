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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_PROVISIONING_SERVICE_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_PROVISIONING_SERVICE_H_

#include <cstdint>
#include <string>

namespace sealed {
namespace wasm {
namespace server {

// This must match the implicit service name used in generated client code
// which is the Rune filename defining the service interface.
// TODO(sidtelang): have the generated header file export this name.
extern const char kServiceName[];

// Method name for retrieving an external key for use in a Sealer.
extern const char kGetExternalSealerKeyMethodName[];

// Context info used by the hybrid encryption scheme for delivering an external
// Sealer key.
extern const char kSealerKeyContextInfo[];

// Method name for getting provisioning challenges from an Eidetic quorum.
// This RPC method is called by the policy enforcer on the hosting Sealet.
extern const char kGetEideticProvisioningChallengesMethodName[];

// Method name for provisioning an Eidetic quorum.
// This RPC method is called by the policy enforcer on the hosting Sealet.
extern const char kProvisionEideticQuorumMethodName[];

// Method name for reading from an Eidetic quorum.
// This RPC method is called by the policy enforcer on the hosting Sealet.
extern const char kReadEideticQuorumMethodName[];

// Method name for writing to an Eidetic quorum.
// This RPC method is called by the policy enforcer on the hosting Sealet.
extern const char kWriteEideticQuorumMethodName[];

// Method name for reading the newest, possibly non-consensus from an Eidetic
// quorum.
// This RPC method is called by the policy enforcer on the hosting Sealet.
extern const char kReadNewestEideticQuorumMethodName[];

using RpcHandler = int (*)(int32_t, int32_t);

extern RpcHandler GetRpcHandler(const std::string& method_name);

}  // namespace server
}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_PROVISIONING_SERVICE_H_
