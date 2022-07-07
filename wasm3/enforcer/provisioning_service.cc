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

#include "third_party/sealedcomputing/wasm3/enforcer/provisioning_service.h"

#include <unordered_map>

#include "third_party/sealedcomputing/wasm3/base.h"
#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/crypto.h"
#include "third_party/sealedcomputing/wasm3/enforcer/hybrid_encryption.h"
#include "third_party/sealedcomputing/wasm3/enforcer/provisioned_state.h"
#include "third_party/sealedcomputing/wasm3/enforcer/provisioning_service.common.h"
#include "third_party/sealedcomputing/wasm3/enforcer/server.h"
#include "third_party/sealedcomputing/wasm3/keyset_policies/emulated_sealer.h"
#include "third_party/sealedcomputing/wasm3/logging.h"
#include "third_party/sealedcomputing/wasm3/status.h"
#include "third_party/sealedcomputing/wasm3/statusor.h"

namespace sealed {
namespace wasm {
namespace server {

using sealed::wasm::ByteString;
using sealed::wasm::kFailedPrecondition;
using sealed::wasm::kInvalidArgument;
using sealed::wasm::kUnauthenticated;
using sealed::wasm::ProvisionedState;
using sealed::wasm::RandBytes;
using sealed::wasm::SecretByteString;
using sealed::wasm::Status;
using sealed::wasm::StatusOr;

namespace {

// Length of the task and group pre-secret.
constexpr size_t kPreSecretLen = 32;

// Length of the secret to use in deriving a x25519 hybrid encryption key.
constexpr size_t kHybridEncryptionSecretLen = 32;

// Returns non-null pointer to ProvisionedState
ProvisionedState* GetProvisionedState() {
  SC_CHECK(!!sealed::wasm::global_server);
  ProvisionedState* provisioned_state =
      sealed::wasm::global_server->GetProvisionedState();
  SC_CHECK_NOT_NULL(provisioned_state);
  return provisioned_state;
}

}  // namespace

StatusOr<ProvisionTaskResponse> ProvisionTask(
    const SealedTaskConfig& task_config) {
  ProvisionedState* provisioned_state = GetProvisionedState();

  if (task_config.sealer_type == SealerType::SEALER_TYPE_EXTERNAL) {
    std::string response;
    sealed::wasm::HybridEncryptionPrivateKey private_key(
        RandBytes(kHybridEncryptionSecretLen));
    SC_RETURN_IF_ERROR(sealed::wasm::global_server->SendSealetRpc(
        kGetExternalSealerKeyMethodName, private_key.GetPublicKey(),
        &response));
    // Remove Tink prefix from response ciphertext.
    response = response.substr(wasm::kTinkPrefixLength);
    SC_ASSIGN_OR_RETURN(SecretByteString aes_gcm_key,
                        private_key.Decrypt(response, kSealerKeyContextInfo));
    provisioned_state->SetTaskConfig(task_config, aes_gcm_key);
  } else {
    provisioned_state->SetTaskConfig(task_config);
  }
  provisioned_state->SetTaskProvisionedState(RandBytes(kPreSecretLen));

  // Set signer on server's SecureListeningSocket instance.
  sealed::wasm::global_server->GetSecureListeningSocket()->SetSelfSigner(
      provisioned_state->GetTaskHandshakeSigner());

  ProvisionTaskResponse response;
  provisioned_state->GetTaskHandshakeSigner()->GetVerifyingKey()->Serialize(
      &response.task_pubkey);

  ByteString ciphertext = provisioned_state->GetSealer()->Encrypt(
      provisioned_state->GetTaskPreSecret(), "");
  response.wrapped_blob = ciphertext.string();

  return response;
}

StatusOr<StartTaskResponse> StartTask(const StartTaskRequest& request) {
  ProvisionedState* provisioned_state = GetProvisionedState();
  SecretByteString task_pre_secret;
  if (request.task_config.sealer_type == SealerType::SEALER_TYPE_EXTERNAL) {
    std::string response;
    sealed::wasm::HybridEncryptionPrivateKey private_key(
        RandBytes(kHybridEncryptionSecretLen));
    SC_RETURN_IF_ERROR(sealed::wasm::global_server->SendSealetRpc(
        kGetExternalSealerKeyMethodName, private_key.GetPublicKey(),
        &response));
    // Remove Tink prefix from response ciphertext.
    response = response.substr(wasm::kTinkPrefixLength);
    SC_ASSIGN_OR_RETURN(SecretByteString aes_gcm_key,
                        private_key.Decrypt(response, kSealerKeyContextInfo));
    provisioned_state->SetTaskConfig(request.task_config, aes_gcm_key);
  } else {
    provisioned_state->SetTaskConfig(request.task_config);
  }

  if (!provisioned_state->GetSealer()->Decrypt(request.wrapped_blob, "",
                                               &task_pre_secret)) {
    return Status(sealed::wasm::kInvalidArgument,
                  "decrypting wrapped_blob failed");
  }
  provisioned_state->SetTaskProvisionedState(task_pre_secret);

  // Set signer on server's SecureListeningSocket instance.
  sealed::wasm::global_server->GetSecureListeningSocket()->SetSelfSigner(
      provisioned_state->GetTaskHandshakeSigner());

  return StartTaskResponse();
}

StatusOr<CallProvisionGroupMemberResponse> CallProvisionGroupMember(
    const CallProvisionGroupMemberRequest& request) {
  ProvisionedState* provisioned_state = GetProvisionedState();
  ProvisionGroupMemberRequest provision_group_member_request{
      .group_config = provisioned_state->GetGroupConfig(),
      .group_pre_secret = provisioned_state->GetGroupPreSecret(),
  };
  EncodedMessage encoded_provision_group_member_request =
      EncodeProvisionGroupMemberRequest(provision_group_member_request);
  std::string encoded_provision_group_response;
  SecretByteString response_secret;
  SC_RETURN_IF_ERROR(sealed::wasm::global_server->SendRpc(
      request.task_pubkey, kServiceName, "ProvisionGroupMember",
      encoded_provision_group_member_request.public_data,
      encoded_provision_group_member_request.secret_data, true,
      &encoded_provision_group_response, &response_secret));
  SC_ASSIGN_OR_RETURN(ProvisionGroupResponse response,
                      DecodeProvisionGroupResponse(
                          ByteString(encoded_provision_group_response)));
  if (!response_secret.empty()) {
    return Status(
        sealed::wasm::kInternal,
        "unexpectedly got secret response from ProvisionGroupMember call");
  }
  return CallProvisionGroupMemberResponse{
      .wrapped_blob = response.wrapped_blob,
  };
}

namespace {

// Validate preconditions for ProvisionGroupGenesis and ProvisionGroupMember.
// Returns self_pubkey.
StatusOr<std::string> ProvisionGroupValidatePreconditions(
    const SealedGroupConfig& group_config,
    const ProvisionedState& provisioned_state) {
  // Validate preconditions.
  std::string self_pubkey;
  if (provisioned_state.GetTaskHandshakeSigner() != nullptr) {
    provisioned_state.GetTaskHandshakeSigner()->GetVerifyingKey()->Serialize(
        &self_pubkey);
  } else {
    return Status(sealed::wasm::kFailedPrecondition,
                  "Task signing key is missing: ProvisionGroup likely called "
                  "before ProvisionTask or StartTask");
  }
  if (provisioned_state.GetSealer() == nullptr) {
    return Status(sealed::wasm::kFailedPrecondition,
                  "Task sealer is missing: ProvisionGroup likely called before "
                  "ProvisionTask or StartTask");
  }
  if (group_config.task_pubkeys.empty()) {
    return Status(kInvalidArgument, "GroupConfig has empty task_pubkeys");
  }
  return self_pubkey;
}

// Prepare response for ProvisionGroupGenesis and ProvisionGroupMember.
ProvisionGroupResponse ProvisionGroupPrepareResponse(
    const SealedGroupConfig& group_config,
    const ProvisionedState& provisioned_state) {
  ProvisionGroupResponse response;
  response.wrapped_blob = provisioned_state.GetSealer()
                              ->Encrypt(provisioned_state.GetGroupPreSecret(),
                                        EncodeSealedGroupConfig(group_config))
                              .string();
  response.group_pubkey =
      provisioned_state.GetGroupEncryptionKey()->GetPublicKey();
  return response;
}
}  // namespace

sealed::wasm::StatusOr<ProvisionGroupResponse> ProvisionGroupGenesis(
    const ProvisionGroupGenesisRequest& request) {
  ProvisionedState* provisioned_state = GetProvisionedState();
  SC_CHECK_NOT_NULL(provisioned_state);
  SC_ASSIGN_OR_RETURN(std::string self_pubkey,
                      ProvisionGroupValidatePreconditions(request.group_config,
                                                          *provisioned_state));

  SecretByteString group_pre_secret;
  if (request.group_config.task_pubkeys.front() == self_pubkey) {
    // Genesis group member is being provisioned.
    // Generate random group pre-secret.
    group_pre_secret = RandBytes(kPreSecretLen);
  } else {
    return Status(kInvalidArgument,
                  "ProvisionGroupGenesis called on non-genesis node");
  }

  // Derive group keys.
  provisioned_state->SetGroupProvisionedState(group_pre_secret,
                                              request.group_config);

  // Wrap group pre-secret and prepare response.
  return ProvisionGroupPrepareResponse(request.group_config,
                                       *provisioned_state);
}

sealed::wasm::StatusOr<ProvisionGroupResponse> ProvisionGroupMember(
    const ProvisionGroupMemberRequest& request) {
  ProvisionedState* provisioned_state = GetProvisionedState();
  SC_CHECK_NOT_NULL(provisioned_state);

  // Validate preconditions.
  SC_ASSIGN_OR_RETURN(std::string self_pubkey,
                      ProvisionGroupValidatePreconditions(request.group_config,
                                                          *provisioned_state));

  SecretByteString group_pre_secret;
  if (request.group_config.task_pubkeys.front() == self_pubkey) {
    return Status(kInvalidArgument,
                  "ProvisionGroupMember called on genesis node");
  } else {
    sealed::wasm::Server::RpcContext* current_rpc_context =
        sealed::wasm::global_server->GetCurrentRpcContext();
    if (!current_rpc_context->socket->IsSecure()) {
      return Status(kUnauthenticated, "incoming RPC was not authenticated");
    }
    sealed::wasm::Socket::EndpointId peer = current_rpc_context->socket->Peer();
    if (peer != request.group_config.task_pubkeys.front()) {
      return Status(
          kFailedPrecondition,
          "authenticated client calling ProvisionGroup is not genesis node");
    }
    group_pre_secret = request.group_pre_secret;
  }

  // Derive group keys.
  provisioned_state->SetGroupProvisionedState(group_pre_secret,
                                              request.group_config);

  // Wrap group pre-secret and prepare response.
  return ProvisionGroupPrepareResponse(request.group_config,
                                       *provisioned_state);
}

StatusOr<StartGroupResponse> StartGroup(const StartGroupRequest& request) {
  ProvisionedState* provisioned_state = GetProvisionedState();
  SecretByteString group_pre_secret;
  if (!provisioned_state->GetSealer()->Decrypt(
          request.wrapped_blob, EncodeSealedGroupConfig(request.group_config),
          &group_pre_secret)) {
    return Status(kInvalidArgument, "decrypting wrapped_blob failed");
  }
  provisioned_state->SetGroupProvisionedState(group_pre_secret,
                                              request.group_config);

  return StartGroupResponse();
}

}  // namespace server
}  // namespace wasm
}  // namespace sealed
