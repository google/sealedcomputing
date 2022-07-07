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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_SOCKET_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_SOCKET_H_

#include <memory>

#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/status.h"

namespace sealed {
namespace wasm {

// Represents one end of a communication channel between two sealed computing
// endpoints. Each `Socket` has exactly one associated
// - endpoint containing it,
// - different `Socket` instance representing the other end of the
//   communication channel. This is called the peer `Socket` of this instance.
//
// An endpoint may contain multiple `Socket` instances at the same time
// representing different open channels with peer endpoints. An endpoint may
// also contain more than one `Socket` for the same peer endpoint.
//
// A `Socket` could be unidirectional in either direction, or bidirectional.
// The endpoint associated with a `Socket` may be an untrusted endpoint without
// a securely-provisioned identity, e.g. the sealet.
// A `Socket` can either be secure (i.e. mutually authenticated and selectively
// encrypted) or insecure.
class Socket {
 public:
  virtual ~Socket() = default;
  // The `payload_secret` fields are encrypted when sent and decrypted when
  // received over secure sockets. These fields are always empty/ignored by
  // insecure sockets.
  virtual void Send(const ByteString& payload,
                    const SecretByteString& payload_secret) = 0;
  virtual Status Recv(ByteString* payload,
                      SecretByteString* payload_secret) = 0;

  // Returns whether this instance is a secure `Socket`.
  virtual bool IsSecure() const = 0;

  using EndpointId = ByteString;
  // Returns an identifier for the endpoint associated with the peer `Socket` of
  // this instance.
  virtual EndpointId Peer() const = 0;
  // Returns an identifier for the endpoint associated with this instance.
  virtual EndpointId Self() const = 0;
};

// Routes incoming messages, on a given input stream, to the `Socket` instance
// they are destined for. This may be an existing `Socket` instance or a new one
// created by this `ListeningSocket` instance.
//
// A `ListeningSocket` is used by sealed computing server endpoints to
// effectively multiplex multiple bidirectional channels on a single incoming
// and outgoing stream (like stdio).
class ListeningSocket {
 public:
  virtual ~ListeningSocket() = default;

  // Called when this instance creates a new `Socket`.
  // The callback is provided
  // - `arg`: a callback-defined argument
  // - `first_message` and `first_message_secret`: the first message and message
  //   secret sent by the peer `Socket` of the newly created `Socket`,
  // - `bidi_socket`: the newly created `Socket` used to subsequently exchange
  //   messages with the peer. This `Socket` is bidirectional.
  // - `err_socket`: a write-only `Socket` to write error messages that are
  //   logged.
  // - `listening_socket`: this ListeningSocket instance.
  // `bidi_socket` and `err_socket` are only guaranteed to be valid until
  // the callback returns.
  using Callback = void (*)(void* arg, const ByteString& first_message,
                            const SecretByteString& first_message_secret,
                            Socket* bidi_socket, Socket* err_socket,
                            ListeningSocket* listening_socket);

  // Continually processes incoming messages and routes them to the `Socket`
  // they are destined for (including newly created `Socket` instances).
  // Listen returns when the incoming stream is closed or broken and is no
  // longer unusable.
  virtual void Listen(Callback callback, void* arg) = 0;

  // Must be called by a callback. This provides the callback with a `Socket`
  // connected to `peer`. The returned `Socket` is secure iff `require_secure`
  // is true.
  virtual StatusOr<std::unique_ptr<Socket>> CreateSocket(
      const Socket::EndpointId& peer, bool require_secure) = 0;
};

}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_SOCKET_H_
