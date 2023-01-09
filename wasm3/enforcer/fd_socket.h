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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_FD_SOCKET_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_FD_SOCKET_H_

#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/enforcer/envelope.common.h"
#include "third_party/sealedcomputing/wasm3/enforcer/socket_internal.h"
#include "third_party/sealedcomputing/wasm3/socket.h"
#include "third_party/sealedcomputing/wasm3/status.h"

namespace sealed {
namespace wasm {

// Ideally, we'd include consts.h from the SimpleSevIo library, but:
// 1) This is not open-source yet, and would break our external builds.
// 2) Only a cc_library target exists, while this code compiles both on the
//    inside of the enclave, and outside.
// TODO(b/259311886): Delete this when we close this bug.
constexpr size_t kSimpleSevIoChunkSize = 4096;

// Uses file descriptors to send and receive messages.
class FdSocket : public SocketInternal {
 public:
  FdSocket(const EndpointId& peer, const EndpointId& self,
           const std::string& socket_id, int in_fd, int out_fd);
  void Send(const ByteString& payload,
            const SecretByteString& payload_secret) override;
  Status Recv(ByteString* payload, SecretByteString* payload_secret) override;
  bool IsSecure() const override { return false; }
  EndpointId Peer() const override { return peer_; }
  EndpointId Self() const override { return self_; }

  void SendEnvelope(const Envelope& envelope) override;
  Status RecvEnvelope(Envelope* envelope) override;
  std::string GetSocketId() const override { return socket_id_; }

 private:
  // Identity of peer endpoint.
  EndpointId peer_;
  // Identity of self endpoint.
  EndpointId self_;
  std::string socket_id_;
  // Does not own the file descriptors.
  int in_fd_;
  int out_fd_;

  friend class FiberListeningSocket;
};

}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_FD_SOCKET_H_
