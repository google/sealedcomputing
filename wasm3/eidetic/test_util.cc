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

#include "third_party/sealedcomputing/wasm3/eidetic/test_util.h"

#include "third_party/absl/status/status.h"
#include "third_party/sealedcomputing/wasm3/eidetic/service.common.h"
#include "util/task/status_macros.h"
#include "util/time/protoutil.h"

namespace sealed {
namespace eidetic {

namespace {

absl::Status CopyProtoToSealed(
    const folsom::eidetic::ProvisionResponse& proto_response,
    SingleProvisionResponse& sealed_response) {
  RETURN_IF_ERROR(CopyProtoToSealed(proto_response.read_response().block(),
                                    sealed_response.eidetic_block));
  for (const auto& hash :
       proto_response.read_response().merkle_proof().challenge()) {
    sealed_response.challenge_merkle_proof.push_back(hash);
  }
  return absl::OkStatus();
}

absl::Status CopyProtoToSealed(
    const folsom::eidetic::ReadResponse& proto_response,
    SingleResponse& sealed_response) {
  RETURN_IF_ERROR(CopyProtoToSealed(proto_response.block(),
                                    sealed_response.eidetic_block));
  sealed_response.state = proto_response.state();
  sealed_response.version = proto_response.version();
  for (const auto& hash :
       proto_response.merkle_proof().challenge()) {
    sealed_response.challenge_merkle_proof.push_back(hash);
  }
  for (const auto& hash :
       proto_response.merkle_proof().state()) {
    sealed_response.state_version_merkle_proof.push_back(hash);
  }
  return absl::OkStatus();
}

}  // namespace

absl::Status CopyProtoToSealed(const folsom::eidetic::EideticBlock& proto_block,
                               EideticBlock& sealed_block) {
  sealed_block.challenges_root = proto_block.challenges_root();
  sealed_block.states_root = proto_block.states_root();
  sealed_block.prev_block_hash = proto_block.prev_block_hash();
  sealed_block.rand_bytes = proto_block.rand_bytes();
  ASSIGN_OR_RETURN(absl::Duration time,
                   util_time::DecodeGoogleApiProto(proto_block.time()));
  sealed_block.time_microseconds = absl::ToInt64Microseconds(time);
  ASSIGN_OR_RETURN(absl::Duration time_delta,
                   util_time::DecodeGoogleApiProto(proto_block.time_delta()));
  sealed_block.time_delta_microseconds = absl::ToInt64Microseconds(time_delta);
  sealed_block.counter = proto_block.counter();
  sealed_block.signature = proto_block.signature();
  return absl::OkStatus();
}

void FakeEideticQuorum::Initialize(uint8_t size) {
  ASSERT_OK(
      folsom::eidetic::testing_internal::MakeContexts(size, client_data_));
  ASSERT_EQ(client_data_.server_infos.size(), size);
  for (const auto& it : client_data_.server_infos) {
    eidetic_stubs_[it.first] =
        it.second->server.MakeStub<folsom::eidetic::EideticService>();
  }
}

void FakeEideticQuorum::GetProvisioningChallenges(
    const eidetic::GetProvisioningChallengesRequest& req,
    eidetic::GetProvisioningChallengesResponse& resp) {
  for (int i = 0; i < req.quorum_public_keys.size(); ++i) {
    folsom::eidetic::GetProvisioningChallengeRequest request;
    folsom::eidetic::GetProvisioningChallengeResponse response;
    ASSERT_OK(
        eidetic_stubs_[req.quorum_public_keys[i]]->GetProvisioningChallenge(
            request, response));
    resp.challenges.push_back(response.challenge());
  }
}

void FakeEideticQuorum::Provision(const eidetic::ProvisionRequest& req,
                                  eidetic::ProvisionResponse& resp) {
  ASSERT_EQ(req.quorum_public_keys.size(), req.thm_encrypted_mac_secret.size());
  for (int i = 0; i < req.quorum_public_keys.size(); ++i) {
    folsom::eidetic::ProvisionRequest request;
    request.set_eidetic_id(req.eidetic_id);
    request.set_challenge(req.challenge);
    request.set_status(folsom::eidetic::STATE_COMMITTED);
    request.set_thm_encrypted_mac_secret(req.thm_encrypted_mac_secret[i]);
    request.set_provisioning_challenge(req.provisioning_challenges[i]);
    request.set_public_key(req.public_key);
    request.set_signature(req.signatures[i]);

    eidetic::SingleProvisionResponse single_response;
    folsom::eidetic::ProvisionResponse response;
    ASSERT_OK(eidetic_stubs_[req.quorum_public_keys[i]]->Provision(request,
                                                                   response));
    ASSERT_OK(CopyProtoToSealed(response, single_response));
    resp.provision_responses.push_back(single_response);
  }
}

void FakeEideticQuorum::Read(const ReadRequest& req, ReadResponse& resp) {
  for (int i = 0; i < req.quorum_public_keys.size(); ++i) {
    folsom::eidetic::ReadRequest request;
    request.set_eidetic_id(req.eidetic_id);
    request.set_challenge(req.challenge);
    request.set_status(folsom::eidetic::STATE_COMMITTED);

    SingleResponse single_response;
    folsom::eidetic::ReadResponse response;
    ASSERT_OK(
        eidetic_stubs_[req.quorum_public_keys[i]]->Read(request, response));
    ASSERT_OK(CopyProtoToSealed(response, single_response));
    resp.responses.push_back(single_response);
  }
}

void FakeEideticQuorum::Write(const WriteRequest& req, WriteResponse& resp) {
  for (int i = 0; i < req.quorum_public_keys.size(); ++i) {
    folsom::eidetic::WriteRequest request;
    request.set_eidetic_id(req.eidetic_id);
    request.set_challenge(req.challenge);
    request.set_new_state(req.new_state);
    request.set_version(req.new_version);
    request.set_mac(req.mac);
    request.set_status(folsom::eidetic::STATE_COMMITTED);

    SingleResponse single_response;
    folsom::eidetic::WriteResponse response;
    ASSERT_OK(
        eidetic_stubs_[req.quorum_public_keys[i]]->Write(request, response));
    ASSERT_OK(CopyProtoToSealed(response.read_response(), single_response));
    resp.responses.push_back(single_response);
  }
}

void FakeEideticQuorum::WriteSingleMember(const WriteRequest& req,
                                          WriteResponse& resp) {
  ASSERT_EQ(req.quorum_public_keys.size(), 1);
  folsom::eidetic::WriteRequest request;
  request.set_eidetic_id(req.eidetic_id);
  request.set_challenge(req.challenge);
  request.set_new_state(req.new_state);
  request.set_version(req.new_version);
  request.set_mac(req.mac);
  request.set_status(folsom::eidetic::STATE_COMMITTED);

  SingleResponse single_response;
  folsom::eidetic::WriteResponse response;
  ASSERT_OK(
      eidetic_stubs_[req.quorum_public_keys.at(0)]->Write(request, response));
  ASSERT_OK(CopyProtoToSealed(response.read_response(), single_response));
  resp.responses.push_back(single_response);
}

void FakeEideticQuorum::ReadNewest(const ReadRequest& req, ReadResponse& resp) {
  uint64_t max_version = 0;
  for (int i = 0; i < req.quorum_public_keys.size(); ++i) {
    folsom::eidetic::ReadRequest request;
    request.set_eidetic_id(req.eidetic_id);
    request.set_challenge(req.challenge);
    request.set_status(folsom::eidetic::STATE_COMMITTED);

    SingleResponse single_response;
    folsom::eidetic::ReadResponse response;
    ASSERT_OK(
        eidetic_stubs_[req.quorum_public_keys[i]]->Read(request, response));
    ASSERT_OK(CopyProtoToSealed(response, single_response));
    resp.responses.push_back(single_response);
    if (response.version() > max_version) max_version = response.version();
  }
  // Zero out all responses that do not match max_version.
  for (auto& response : resp.responses) {
    if (response.version != max_version) response = SingleResponse();
  }
}

}  // namespace eidetic
}  // namespace sealed
