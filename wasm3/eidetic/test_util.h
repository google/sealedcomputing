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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_EIDETIC_TEST_UTIL_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_EIDETIC_TEST_UTIL_H_

#include "security/folsom/eidetic/proto/eidetic.proto.h"
#include "security/sealedcomputing/boq/eidetic/client/testing/util.h"
#include "third_party/sealedcomputing/wasm3/base.h"
#include "third_party/sealedcomputing/wasm3/eidetic/service.common.h"
#include "third_party/sealedcomputing/wasm3/enforcer/rpc.common.h"
#include "third_party/sealedcomputing/wasm3/enforcer/socket_internal.h"
#include "third_party/sealedcomputing/wasm3/enforcer/status_encode_decode.h"

namespace sealed {
namespace eidetic {

absl::Status CopyProtoToSealed(const folsom::eidetic::EideticBlock& proto_block,
                               sealed::eidetic::EideticBlock& sealed_block);

// Testing fake. Uses ASSERT_* macros for invariants in test code.
class FakeEideticQuorum {
 public:
  void Initialize(uint8_t size);

  void GetProvisioningChallenges(const GetProvisioningChallengesRequest& req,
                                 GetProvisioningChallengesResponse& resp);

  void Provision(const ProvisionRequest& req, ProvisionResponse& resp);

  void Read(const ReadRequest& req, ReadResponse& resp);

  void Write(const WriteRequest& req, WriteResponse& resp);

  void WriteSingleMember(const WriteRequest& req, WriteResponse& resp);

  void ReadNewest(const ReadRequest& req, ReadResponse& resp);

  folsom::eidetic::testing_internal::DynamicClientData client_data_;
  // Stores a (Eidetic pubkey) -> (EideticService stub) map.
  std::unordered_map<std::string,
                     std::unique_ptr<folsom::eidetic::EideticService>>
      eidetic_stubs_;
};

// Receives a message on `socket`, asserting the `rpc_type` and
// `method_name` of the message.
// Uses `decoder` to decode the message payload and writes out to `socket_id`
// and `message`.
template <typename T>
void RecvMessage(const wasm::RpcType& expected_rpc_type,
                 const std::string& method_name, wasm::StatusOr<T>& message,
                 std::string& socket_id, wasm::SocketInternal& socket,
                 wasm::StatusOr<T> (*decoder)(const wasm::EncodedMessage&)) {
  wasm::RpcType rpc_type = wasm::RpcType::RPC_TYPE_UNKNOWN;
  wasm::RpcMessage rpc_message;
  while (rpc_type != expected_rpc_type) {
    wasm::Envelope envelope;
    SC_ASSERT_OK(socket.RecvEnvelope(&envelope));
    ASSERT_FALSE(envelope.socket_id.empty());
    socket_id = envelope.socket_id;

    ASSERT_EQ(envelope.payload_type,
              wasm::PayloadType::PAYLOAD_TYPE_RPC_MESSAGE);
    SC_ASSERT_OK_AND_ASSIGN(
        rpc_message,
        wasm::DecodeRpcMessage(wasm::ByteString(envelope.payload)));
    rpc_type = rpc_message.type;
  }
  ASSERT_EQ(rpc_message.method_name, method_name);
  if (!rpc_message.encoded_status.empty()) {
    wasm::Status status;
    ASSERT_OK(wasm::DecodeStatus(rpc_message.encoded_status, &status));
    if (!status.ok()) {
      message = status;
      return;
    }
  }
  message = decoder(wasm::ByteString(rpc_message.payload));
}

// Send a RPC message of "response" type on `socket`.
inline void SendResponseMessage(const std::string encoded_message,
                                const std::string& socket_id,
                                wasm::SocketInternal& socket) {
  socket.SendEnvelope(wasm::Envelope{
      .socket_id = socket_id,
      .payload_type = wasm::PayloadType::PAYLOAD_TYPE_RPC_MESSAGE,
      .payload = EncodeRpcMessage(wasm::RpcMessage{
                                      .type = wasm::RpcType::RPC_TYPE_RESPONSE,
                                      .payload = encoded_message,
                                  })
                     .public_data,
  });
}

}  // namespace eidetic
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_EIDETIC_TEST_UTIL_H_
