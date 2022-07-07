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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_SECURE_SOCKET_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_SECURE_SOCKET_H_

#include <cstdint>
#include <memory>

#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/enforcer/socket_internal.h"
#include "third_party/sealedcomputing/wasm3/handshaker.h"
#include "third_party/sealedcomputing/wasm3/keyset_policies/p256_sign.h"
#include "third_party/sealedcomputing/wasm3/socket.h"
#include "third_party/sealedcomputing/wasm3/status.h"
#include "third_party/sealedcomputing/wasm3/statusor.h"

namespace sealed {
namespace wasm {

// Contains secure session secrets and state.
// Note: a secure session exists between two endpoints, and therefore can
// be shared by multiple socket pairs.
struct SecureSession {
  SessionSecrets secrets;
  // Expected `Envelope::sessionEnvelopeNum` on the next Envelope to be
  // exchanged over this session.
  uint64_t envelope_num = 0;
};

// Creates a new secure session between an endpoint identified by `self_signer`
// (which initiates the secure session as a client) and the peer endpoint
// of `socket`.
StatusOr<std::unique_ptr<SecureSession>> CreateSecureSession(
    SocketInternal* socket, const P256Sign* self_signer);

// For a given request to initiate a secure session (i.e.
// `first_handshake_message`) from the peer endpoint of `socket`, this function
// continues the secure session establishment protocol (a.k.a. handshake
// protocol) with the peer.
StatusOr<std::unique_ptr<SecureSession>> AcceptSecureSession(
    Socket* socket, const std::string& first_handshake_message,
    const P256Sign* self_signer);

// Sends and receives messages over a mutually authenticated and selectively
// encrypted channel.
class SecureSocket : public Socket {
 public:
  // `base_socket` and `session` must outlive this instance.
  // This instance does not take ownership of `base_socket` or `session`.
  SecureSocket(SocketInternal* base_socket, SecureSession* session)
      : base_socket_(base_socket), session_(session) {}

  void Send(const ByteString& payload,
            const SecretByteString& payload_secret) override;
  Status Recv(ByteString* payload, SecretByteString* payload_secret) override;
  bool IsSecure() const override { return true; }
  EndpointId Peer() const override { return base_socket_->Peer(); }
  EndpointId Self() const override { return base_socket_->Self(); }

 private:
  SocketInternal* base_socket_;
  SecureSession* session_;
};

std::string IntegerToAesGcmNonceForTesting(uint64_t n);

}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_SECURE_SOCKET_H_
