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

#include "third_party/sealedcomputing/wasm3/eidetic/api.h"

#include <endian.h>

#include <cstdint>
#include <utility>

#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/crypto.h"
#include "third_party/sealedcomputing/wasm3/eidetic/service.common.h"
#include "third_party/sealedcomputing/wasm3/eidetic/util.h"
#include "third_party/sealedcomputing/wasm3/enforcer/crypto_internal.h"
#include "third_party/sealedcomputing/wasm3/enforcer/provisioned_state.h"
#include "third_party/sealedcomputing/wasm3/enforcer/provisioning_service.common.h"
#include "third_party/sealedcomputing/wasm3/enforcer/provisioning_service.h"
#include "third_party/sealedcomputing/wasm3/enforcer/server.h"
#include "third_party/sealedcomputing/wasm3/status.h"
#include "third_party/sealedcomputing/wasm3/statusor.h"

namespace sealed {
namespace eidetic {

namespace {

using ::sealed::wasm::ByteString;
using ::sealed::wasm::EideticConfig;
using ::sealed::wasm::ProvisionedState;
using ::sealed::wasm::SecretByteString;
using ::sealed::wasm::Status;
using ::sealed::wasm::StatusOr;
using ::sealed::wasm::enforcer::HmacSha256;

constexpr char kEideticWriteStateMacPrefix[] = "writeState";

StatusOr<const ProvisionedState*> GetProvisionedState() {
  SC_CHECK(!!sealed::wasm::global_server);
  ProvisionedState* provisioned_state =
      sealed::wasm::global_server->GetProvisionedState();
  if (provisioned_state == nullptr) {
    return Status(wasm::kFailedPrecondition, "no provisioned state found");
  }
  return provisioned_state;
}

ByteString ComputeMac(const SecretByteString& mac_key,
                      const std::string& eidetic_id, const std::string& state,
                      uint64_t version) {
  auto hmac = HmacSha256(mac_key, kEideticWriteStateMacPrefix);
  hmac.Update(eidetic_id);
  hmac.Update(state);
  uint64_t version_le = htole64(version);
  hmac.Update(ByteString(&version_le, sizeof(version_le)));
  return hmac.Final();
}

StatusOr<EideticState> VerifySingleResponses(
    const EideticConfig& eidetic_config, const std::string& eidetic_id,
    const std::string& challenge,
    const std::vector<SingleResponse>& responses) {
  if (eidetic_config.signature_public_keys.size() != responses.size()) {
    return Status(wasm::kInvalidArgument,
                  "incomplete response: fewer responses than quorum members");
  }
  std::pair<EideticState, uint8_t> state_count = {};
  for (size_t i = 0; i < eidetic_config.signature_public_keys.size(); ++i) {
    const std::string& pubkey = eidetic_config.signature_public_keys[i];
    const SingleResponse& single_response = responses[i];
    // An empty SingleResponse means the Sealet determined this SingleResponse
    // is not in a threshold number of SingleResponses required to verify
    // the Eidetic read.
    if (single_response.state.empty()) continue;

    StatusOr<bool> block_verified =
        VerifyEideticBlock(pubkey, single_response.eidetic_block);
    if (!block_verified.ok() || !*block_verified) {
      SC_LOG(ERROR) << "Error verifying Eidetic block from pubkey: "
                    << wasm::ByteString(pubkey).hex();
      continue;
    }
    if (!VerifyMerkleProof(single_response.challenge_merkle_proof,
                           single_response.eidetic_block.challenges_root,
                           LeafHashFromChallenge(challenge))) {
      SC_LOG(ERROR) << "Error verifying challenge Merkle proof from pubkey: "
                    << wasm::ByteString(pubkey).hex();
      continue;
    }
    if (!VerifyMerkleProof(
            single_response.state_version_merkle_proof,
            single_response.eidetic_block.states_root,
            LeafHashFromEideticIdAndState(eidetic_id, single_response.state,
                                          single_response.version))) {
      SC_LOG(ERROR) << "Error verifying state Merkle proof from pubkey: "
                    << wasm::ByteString(pubkey).hex();
      continue;
    }

    if (state_count.second != 0 &&
        (state_count.first.digest != single_response.state ||
         state_count.first.version != single_response.version)) {
      return Status(wasm::kInvalidArgument, "different state version");
    }
    state_count.first.digest = single_response.state;
    state_count.first.version = single_response.version;
    ++state_count.second;
  }

  // TODO(b/258208004): re-sync state in quorum members if out of sync.
  // Return state if count for it exceeds threshold.
  if (state_count.second < eidetic_config.threshold) {
    return Status(wasm::kUnauthenticated, "did not meet threshold response");
  }
  return state_count.first;
}

struct EideticParams {
  EideticParams(const std::string& id, const EideticConfig& config,
                const SecretByteString& key)
      : eidetic_id(id), eidetic_config(config), task_hmac_key(key) {}
  const std::string eidetic_id;
  const EideticConfig& eidetic_config;
  const SecretByteString& task_hmac_key;
};

EideticParams GetEideticParams(const ProvisionedState* provisioned_state) {
  std::string task_pubkey;
  provisioned_state->GetTaskBytecodeSigner()->GetVerifyingKey()->Serialize(
      &task_pubkey);
  return EideticParams(wasm::Sha256::Digest(task_pubkey),
                       provisioned_state->GetTaskConfig().eidetic_config,
                       provisioned_state->GetTaskHmacKey());
}

}  // namespace

StatusOr<std::string> EideticQuorum::ReadConsensus() {
  // Make Read call to Sealet.
  SC_ASSIGN_OR_RETURN(auto provisioned_state, GetProvisionedState());
  EideticParams params = GetEideticParams(provisioned_state);
  ReadRequest request;
  request.eidetic_id = params.eidetic_id;
  request.quorum_public_keys = params.eidetic_config.signature_public_keys;
  request.threshold = params.eidetic_config.threshold;
  request.challenge = wasm::RandBytes(32);
  std::string encoded_response;
  SC_RETURN_IF_ERROR(sealed::wasm::global_server->SendSealetRpc(
      wasm::server::kReadEideticQuorumMethodName,
      EncodeReadRequest(request).public_data, &encoded_response));
  SC_ASSIGN_OR_RETURN(ReadResponse response,
                      DecodeReadResponse(ByteString(encoded_response)));

  SC_ASSIGN_OR_RETURN(
      state_, VerifySingleResponses(params.eidetic_config, request.eidetic_id,
                                    request.challenge, response.responses));
  return state_.value().digest;
}

Status EideticQuorum::WriteConsensus(const EideticState& new_state) {
  // Make Write call to Sealet.
  SC_ASSIGN_OR_RETURN(auto provisioned_state, GetProvisionedState());
  EideticParams params = GetEideticParams(provisioned_state);
  WriteRequest request;
  request.eidetic_id = params.eidetic_id;
  request.quorum_public_keys = params.eidetic_config.signature_public_keys;
  request.threshold = params.eidetic_config.threshold;
  request.challenge = wasm::RandBytes(32);
  request.new_state = new_state.digest;
  request.new_version = new_state.version;
  request.mac = ComputeMac(params.task_hmac_key, request.eidetic_id,
                           request.new_state, request.new_version);
  std::string encoded_response;
  SC_RETURN_IF_ERROR(sealed::wasm::global_server->SendSealetRpc(
      wasm::server::kWriteEideticQuorumMethodName,
      EncodeWriteRequest(request).public_data, &encoded_response));
  SC_ASSIGN_OR_RETURN(WriteResponse response,
                      DecodeWriteResponse(ByteString(encoded_response)));

  // Verify and collect responses.
  SC_ASSIGN_OR_RETURN(
      EideticState written_state,
      VerifySingleResponses(params.eidetic_config, request.eidetic_id,
                            request.challenge, response.responses));
  if (written_state.digest != new_state.digest ||
      written_state.version != new_state.version) {
    return Status(wasm::kInternal,
                  "written state does not match expected state");
  }
  state_ = written_state;
  return Status();
}

wasm::Status EideticQuorum::WriteConsensus(const std::string& new_state) {
  if (!state_.has_value()) {
    return wasm::Status(
        wasm::kFailedPrecondition,
        "EideticQuorum: WriteConsensus called before ReadConsensus");
  }
  EideticState new_eidetic_state;
  new_eidetic_state.digest = new_state;
  new_eidetic_state.version = state_.value().version + 1;
  return WriteConsensus(new_eidetic_state);
}

wasm::StatusOr<std::string> EideticQuorum::HealConsensus() {
  SC_ASSIGN_OR_RETURN(EideticState state, ReadNewest());
  state.version++;
  SC_RETURN_IF_ERROR(WriteConsensus(state));
  return state_.value().digest;
}

wasm::StatusOr<EideticState> EideticQuorum::ReadNewest() {
  SC_ASSIGN_OR_RETURN(auto provisioned_state, GetProvisionedState());
  EideticParams params = GetEideticParams(provisioned_state);
  ReadRequest request;
  request.eidetic_id = params.eidetic_id;
  request.quorum_public_keys = params.eidetic_config.signature_public_keys;
  request.challenge = wasm::RandBytes(32);
  std::string encoded_response;
  SC_RETURN_IF_ERROR(sealed::wasm::global_server->SendSealetRpc(
      wasm::server::kReadNewestEideticQuorumMethodName,
      EncodeReadRequest(request).public_data, &encoded_response));
  SC_ASSIGN_OR_RETURN(ReadResponse response,
                      DecodeReadResponse(ByteString(encoded_response)));

  // Set threshold=1 in the EideticConfig used to verify responses: at least
  // one verified SingleResponse suffices.
  EideticConfig eidetic_config = params.eidetic_config;
  eidetic_config.threshold = 1;
  return VerifySingleResponses(eidetic_config, request.eidetic_id,
                               request.challenge, response.responses);
}

wasm::ByteString ComputeMacForTesting(const wasm::SecretByteString& mac_key,
                                      const std::string& eidetic_id,
                                      const std::string& state,
                                      uint64_t version) {
  return ComputeMac(mac_key, eidetic_id, state, version);
}

wasm::StatusOr<EideticState> VerifySingleResponsesForTesting(
    const wasm::EideticConfig& eidetic_config, const std::string& eidetic_id,
    const std::string& challenge,
    const std::vector<SingleResponse>& responses) {
  return VerifySingleResponses(eidetic_config, eidetic_id, challenge,
                               responses);
}
}  // namespace eidetic
}  // namespace sealed
