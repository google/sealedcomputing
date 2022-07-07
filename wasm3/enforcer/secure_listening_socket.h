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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_SECURE_LISTENING_SOCKET_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_SECURE_LISTENING_SOCKET_H_

#include <string>
#include <unordered_map>

#include "third_party/sealedcomputing/wasm3/enforcer/secure_socket.h"
#include "third_party/sealedcomputing/wasm3/enforcer/socket_internal.h"
#include "third_party/sealedcomputing/wasm3/keyset_policies/p256_sign.h"
#include "third_party/sealedcomputing/wasm3/socket.h"

namespace sealed {
namespace wasm {

// Routes incoming messages to their destined socket, and additionally
// establishes secure sessions when the incoming message is a handshake request
// (i.e. the first frame in the handshake protocol).
class SecureListeningSocket : public ListeningSocket {
 public:
  SecureListeningSocket(
      std::unique_ptr<ListeningSocketInternal> base_listening_socket);

  // Calls `callback` when an incoming message is destined for a socket
  // that does not exist. This socket is created and supplied to the callback.
  // Additionally, if
  // - the incoming message is a handshake request, and
  // - SetSelfSigner has been called on this instance,
  // then `Listen` completes the handshake and the newly created socket is a
  // secure socket that uses the `SecureSession` established in the handshake.
  void Listen(Callback callback, void* arg) override;

  // Sets the signing key used by the server-side handshakes performed by this
  // instance.
  void SetSelfSigner(P256Sign* self_signer) {
    self_signer_ = self_signer;
    std::string self_endpoint_id;
    self_signer->GetVerifyingKey()->Serialize(&self_endpoint_id);
    base_listening_socket_->SetSelfEndpointId(self_endpoint_id);
  }

  P256Sign* GetSelfSigner() const { return self_signer_; }

  // Takes ownership of a `SecureSession` established with a given `peer`.
  void AddSecureSession(const Socket::EndpointId& peer,
                        std::unique_ptr<SecureSession> secure_session) {
    peer_to_secure_session_map_[peer.string()] = std::move(secure_session);
  }

  // Returns nullptr if session with `peer` does not exist.
  SecureSession* GetSecureSession(const Socket::EndpointId& peer) const;

  // Returned socket yields to the main listen loop when blocked on a Recv call.
  StatusOr<std::unique_ptr<Socket>> CreateSocket(const Socket::EndpointId& peer,
                                                 bool require_secure) override;

 private:
  // Identical to `SecureSocket` except the destructor cleans up associated
  // state with the `SecureListeningSocket` instance that created it.
  // `SecureListeningSocket::CreateSocket` returns instances of this class when
  // creating secure sockets.
  class SecureSocketInternal : public SecureSocket {
   public:
    SecureSocketInternal(SocketInternal* base_socket, SecureSession* session,
                         SecureListeningSocket* creator_listening_socket);
    ~SecureSocketInternal();

   private:
    SecureListeningSocket* creator_listening_socket_;
    const std::string socket_id_;
  };

  P256Sign* self_signer_;
  std::unordered_map<std::string, std::unique_ptr<SecureSession>>
      peer_to_secure_session_map_;
  std::unique_ptr<ListeningSocketInternal> base_listening_socket_;

  // This instance owns `SocketInternal` instances used as base sockets for the
  // `SecureSocketInternal` instances it creates.
  std::unordered_map<std::string, std::unique_ptr<SocketInternal>>
      socket_id_to_base_socket_map_;
};

}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_SECURE_LISTENING_SOCKET_H_
