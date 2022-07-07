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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_FIBER_LISTENING_SOCKET_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_FIBER_LISTENING_SOCKET_H_

#include <memory>
#include <unordered_map>

#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/enforcer/envelope.common.h"
#include "third_party/sealedcomputing/wasm3/enforcer/fd_socket.h"
#include "third_party/sealedcomputing/wasm3/enforcer/lite_fiber.h"
#include "third_party/sealedcomputing/wasm3/enforcer/socket_internal.h"
#include "third_party/sealedcomputing/wasm3/socket.h"

namespace sealed {
namespace wasm {

// Uses a lightweight fibers implementation to multiplex multiple sockets
// onto single incoming, outgoing, and error sockets. Callbacks execute in
// a fiber context that yield to the "main listen loop" when blocked on a
// Recv/RecvEnvelope call. The "main listen loop" refers to the event
// loop executed in `Listen` that processes incoming messages.
class FiberListeningSocket : public ListeningSocketInternal {
 public:
  // `in_socket` is a read-only socket.
  // `out_socket` and `err_socket` are write-only sockets.
  FiberListeningSocket(const Socket::EndpointId& self,
                       std::unique_ptr<SocketInternal> in_socket,
                       std::unique_ptr<SocketInternal> out_socket,
                       std::unique_ptr<Socket> err_socket);

  // Errors in reading or parsing incoming messages are written to an outgoing
  // error stream.
  void Listen(InternalCallback callback, void* arg) override;

  void SetSelfEndpointId(const Socket::EndpointId& self) override {
    self_ = self;
  }

  // Returns a `FiberSocket` that yields to the main listen loop when blocked on
  // a Recv/RecvEnvelope call.
  StatusOr<std::unique_ptr<SocketInternal>> CreateSocket(
      const Socket::EndpointId& peer, bool require_secure) override;

 private:
  // Wraps every fiber created by a `FiberListeningSocket` instance.
  struct FiberWrapper {
    std::unique_ptr<FiberInterface> fiber;
    // Every fiber created by this `FiberListeningSocket` instance is associated
    // with a callback invocation for an incoming message. This is the
    // `socket_id` associated with that incoming message.
    std::string socket_id;
  };

  // Supplied to callbacks as a `SocketInternal`.
  // They use an internal unidirectional `SocketInternal` to send outgoing
  // messages, and yield to the `FiberListeningSocket` listen loop to receive
  // incoming messages.
  class FiberSocket : public SocketInternal {
   public:
    // `out_socket`, `fiber` and `fiber_listening_socket` must outlive this
    // instance. This instance does not take ownership of any of the above.
    FiberSocket(const Socket::EndpointId& peer, const Socket::EndpointId& self,
                const std::string& socket_id_, SocketInternal* out_socket,
                FiberWrapper* fiber,
                FiberListeningSocket* fiber_listening_socket);
    ~FiberSocket();
    void Send(const ByteString& payload,
              const SecretByteString& payload_secret) override;
    Status Recv(ByteString* payload, SecretByteString* payload_secret) override;

    void SendEnvelope(const Envelope& envelope) override;
    Status RecvEnvelope(Envelope* envelope) override;
    std::string GetSocketId() const override { return socket_id_; }

    bool IsSecure() const override { return false; }
    EndpointId Peer() const override { return peer_; }
    EndpointId Self() const override { return self_; }

   private:
    // Used for outgoing messages only.
    const Socket::EndpointId peer_;
    const Socket::EndpointId self_;
    const std::string socket_id_;
    SocketInternal* out_socket_;

    FiberWrapper* fiber_;
    FiberListeningSocket* fiber_listening_socket_;

    Envelope incoming_envelope_;
    bool incoming_envelope_available_ = false;

    friend class FiberListeningSocket;
  };

  // There are two kinds of `FiberSocket` instances created by this
  // `FiberListeningSocket` instance:
  // - those created by `Listen` for a new callback invocation
  // - those created by a `CreateSocket` call.
  // The former are owned by the `FiberListeningSocket` instance and the latter
  // are not. This function searches for a `FiberSocket` by `socket_id` among
  // both kinds. Returns `nullptr` if the `FiberSocket` is not found.
  FiberSocket* FindFiberSocket(const std::string& socket_id);

  // Self identity.
  Socket::EndpointId self_;

  std::unique_ptr<SocketInternal> in_socket_;
  std::unique_ptr<SocketInternal> out_socket_;
  std::unique_ptr<Socket> err_socket_;

  std::unique_ptr<LiteFiber> top_level_fiber_;
  // Map from socket_id to unowned `FiberSocket` instances i.e. those created by
  // a `CreateSocket` call.
  std::unordered_map<std::string, FiberSocket*>
      socket_id_to_unowned_fiber_socket_map_;
  // Map from socket_id to owned `FiberSocket` instances i.e. those created by
  // by `Listen` for a new callback invocation.
  std::unordered_map<std::string, std::unique_ptr<FiberSocket>>
      socket_id_to_fiber_socket_map_;
  // Each callback invocation corresponds to a `Fiber` instance.
  std::unordered_map<std::string, std::unique_ptr<FiberWrapper>>
      socket_id_to_fiber_map_;
  // When in a callback, this is always set to the `FiberWrapper` instance
  // associated with that callback invocation.
  FiberWrapper* current_fiber_ = nullptr;
};

std::string RandomSocketIdForTesting();

}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_FIBER_LISTENING_SOCKET_H_
