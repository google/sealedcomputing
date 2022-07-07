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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_SOCKET_INTERNAL_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_SOCKET_INTERNAL_H_

#include "third_party/sealedcomputing/wasm3/enforcer/envelope.common.h"
#include "third_party/sealedcomputing/wasm3/socket.h"
#include "third_party/sealedcomputing/wasm3/status.h"

namespace sealed {
namespace wasm {

// Extends the `Socket` interface by providing the caller access to fields of
// the internal struct used to encapsulate and serialize messages exchanged over
// `Socket` instances.
class SocketInternal : public Socket {
 public:
  virtual ~SocketInternal() = default;

  // Serializes and sends `envelope` to the peer `Socket`.
  virtual void SendEnvelope(const Envelope& envelope) = 0;

  // Deserializes incoming message from peer `Socket` and writes it to
  // `envelope`.
  virtual Status RecvEnvelope(Envelope* envelope) = 0;

  // Returns a globally unique identifier for this `Socket`.
  virtual std::string GetSocketId() const = 0;
};

// Identical to a `ListeningSocket`, except it routes incoming messages to the
// `SocketInternal` they are destined for, creating new `SocketInternal`
// instances as required.
class ListeningSocketInternal {
 public:
  virtual ~ListeningSocketInternal() = default;

  // Identical to `ListeningSocket::Callback` except the callback is provided
  // a newly created bidirectional `SocketInternal` instance and this
  // `ListeningSocketInternal` instance.
  using InternalCallback = void (*)(void* arg, const Envelope& first_envelope,
                                    SocketInternal* bidi_socket,
                                    Socket* err_socket,
                                    ListeningSocketInternal* listening_socket);

  virtual void Listen(InternalCallback callback, void* arg) = 0;

  // Sets an identifier for the endpoint containing this
  // `ListeningSocketInternal` instance. All subsequently created
  // `SocketInternal` instances identify their containing endpoint as `self`.
  virtual void SetSelfEndpointId(const Socket::EndpointId& self) = 0;

  // Identical to `ListeningSocket::CreateSocket` except the returned socket
  // is a `SocketInternal` instance.
  virtual StatusOr<std::unique_ptr<SocketInternal>> CreateSocket(
      const Socket::EndpointId& peer, bool require_secure) = 0;
};

}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_SOCKET_INTERNAL_H_
