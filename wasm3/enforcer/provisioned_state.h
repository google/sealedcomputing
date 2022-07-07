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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_PROVISIONED_STATE_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_PROVISIONED_STATE_H_

#include <memory>

#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/enforcer/hybrid_encryption.h"
#include "third_party/sealedcomputing/wasm3/enforcer/provisioning_service.common.h"
#include "third_party/sealedcomputing/wasm3/keyset_policies/p256_sign.h"
#include "third_party/sealedcomputing/wasm3/keyset_policies/sealer.h"
#include "third_party/sealedcomputing/wasm3/keyset_policies/task_sealer.h"
#include "third_party/sealedcomputing/wasm3/status.h"

namespace sealed {
namespace wasm {

// Purpose string used to sign bytecode-supplied messages.
constexpr char kBytecodeSigningPurpose[] =
    "signing purpose: sealed computing v0: bytecode quoting";

// Contains the state of ProvisioningService. This includes trusted application
// state (secrets and config structs) created or acquired during task and group
// provisioning. This also includes state provided by hardware.
class ProvisionedState {
 public:
  // Copies in `task_config` and establishes a sealer. If `task_config`
  // specifies an external key, then `external_key` must be a raw 128-bit
  // AES-GCM-SIV private key.
  void SetTaskConfig(const SealedTaskConfig& task_config,
                     const SecretByteString& external_key = "");

  // Copies in `task_pre_secret` and derives task keys. Requires SetTaskConfig
  // to have been called already.
  void SetTaskProvisionedState(const SecretByteString& task_pre_secret);

  // Copies in `group_pre_secret` and `group_config` and derives group keys.
  void SetGroupProvisionedState(const SecretByteString& group_pre_secret,
                                const SealedGroupConfig& group_config);

  const SealedTaskConfig& GetTaskConfig() const { return task_config_; }

  P256Sign* GetTaskHandshakeSigner() const {
    return task_handshake_signer_.get();
  }

  void SetTaskHandshakeSignerForTesting(std::unique_ptr<P256Sign> signer) {
    task_handshake_signer_ = std::move(signer);
  }

  const P256Sign* GetTaskBytecodeSigner() const {
    return task_bytecode_signer_.get();
  }

  const SecretByteString& GetTaskPreSecret() const { return task_pre_secret_; }

  const SealedGroupConfig& GetGroupConfig() const { return group_config_; }

  const HybridEncryptionPrivateKey* GetGroupEncryptionKey() const {
    return group_he_privkey_.get();
  }

  const SecretByteString& GetGroupPreSecret() const {
    return group_pre_secret_;
  }

  // Returns a Sealer that binds and wraps/unwraps data to a task config.
  Sealer* GetSealer() const { return sealer_.get(); }

 private:
  // Derives task keys from `task_config` and `task_pre_secret` where each key
  // is bound to `task_config` and the purpose of the key.
  void DeriveTaskKeys();

  // Derives group keys from `group_config` and `group_pre_secret` where each
  // key is bound to `group_config` and the purpose of the key.
  void DeriveGroupKeys();

  // Derives a TaskSealer that binds and wraps/unwraps plaintext to
  // `task_config_`. The TaskSealer instance configuration will be based on
  // sealerType specified in `task_config_`.
  //
  // `external_key` is only used if the kExternal Sealer type is specified. In
  // that case, `external_key` should be assigned a 128-bit AES-GCM-SIV private
  // key.
  void DeriveTaskSealer(const SecretByteString& external_key);

  // A Sealer which encrypts and binds user content to customer tasks.
  std::unique_ptr<TaskSealer> sealer_;

  SealedTaskConfig task_config_;

  // Randomly generated.
  SecretByteString task_pre_secret_;
  // Task signing key used to sign handshake frames.
  std::unique_ptr<P256Sign> task_handshake_signer_;
  // Task signing key used to attest data from the bytecode.
  std::unique_ptr<P256Sign> task_bytecode_signer_;

  SealedGroupConfig group_config_;
  // Randomly generated and shared between group members during group
  // provisioning,
  SecretByteString group_pre_secret_;
  std::unique_ptr<HybridEncryptionPrivateKey> group_he_privkey_;
};

}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_PROVISIONED_STATE_H_
