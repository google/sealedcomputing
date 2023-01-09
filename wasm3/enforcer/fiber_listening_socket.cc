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

#include "third_party/sealedcomputing/wasm3/enforcer/fiber_listening_socket.h"

#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/crypto.h"
#include "third_party/sealedcomputing/wasm3/enforcer/envelope.common.h"
#include "third_party/sealedcomputing/wasm3/enforcer/fd_socket.h"
#include "third_party/sealedcomputing/wasm3/statusor.h"

namespace sealed {
namespace wasm {

using EndpointId = Socket::EndpointId;

namespace {

struct FiberArg {
  SocketInternal* bidi_socket;
  Socket* err_socket;
  ListeningSocketInternal::InternalCallback callback;
  void* callback_arg;
  Envelope first_envelope;
  ListeningSocketInternal* listening_socket;
};

void NewChannel(void* uncast_arg, FiberInterface* fiber) {
  auto arg = static_cast<FiberArg*>(uncast_arg);
  arg->callback(arg->callback_arg, arg->first_envelope, arg->bidi_socket,
                arg->err_socket, arg->listening_socket);
  delete (arg);
}

std::string RandomSocketId() { return RandBytes(8).string(); }

}  // namespace

std::string RandomSocketIdForTesting() { return RandomSocketId(); }

FiberListeningSocket::FiberSocket::FiberSocket(
    const Socket::EndpointId& peer, const Socket::EndpointId& self,
    const std::string& socket_id, SocketInternal* out_socket,
    FiberWrapper* fiber, FiberListeningSocket* fiber_listening_socket)
    : peer_(peer),
      self_(self),
      socket_id_(socket_id),
      out_socket_(out_socket),
      fiber_(fiber),
      fiber_listening_socket_(fiber_listening_socket) {}

FiberListeningSocket::FiberSocket::~FiberSocket() {
  // If this instance was created by `FiberListeningSocket::CreateFiberSocket`
  // then attempt to cleanup associated `FiberListeningSocket` state.
  fiber_listening_socket_->socket_id_to_unowned_fiber_socket_map_.erase(
      out_socket_->GetSocketId());
}

void FiberListeningSocket::FiberSocket::Send(
    const ByteString& payload, const SecretByteString& payload_secret) {
  Envelope envelope;
  envelope.dst = peer_.string();
  envelope.src = self_.string();
  envelope.socket_id = socket_id_;
  envelope.payload_type = PayloadType::PAYLOAD_TYPE_RPC_MESSAGE;
  envelope.payload = payload.string();
  out_socket_->SendEnvelope(envelope);
}

Status FiberListeningSocket::FiberSocket::Recv(
    ByteString* payload, SecretByteString* payload_secret) {
  Envelope envelope;
  SC_RETURN_IF_ERROR(RecvEnvelope(&envelope));
  *payload = envelope.payload;
  payload_secret->clear();
  return Status();
}

void FiberListeningSocket::FiberSocket::SendEnvelope(const Envelope& envelope) {
  out_socket_->SendEnvelope(envelope);
}

Status FiberListeningSocket::FiberSocket::RecvEnvelope(Envelope* envelope) {
  if (!incoming_envelope_available_) {
    fiber_->fiber->Yield();
  }
  *envelope = incoming_envelope_;
  incoming_envelope_available_ = false;
  return Status();
}

FiberListeningSocket::FiberListeningSocket(
    const EndpointId& self, std::unique_ptr<SocketInternal> in_socket,
    std::unique_ptr<SocketInternal> out_socket,
    std::unique_ptr<Socket> err_socket)
    : self_(self),
      in_socket_(std::move(in_socket)),
      out_socket_(std::move(out_socket)),
      err_socket_(std::move(err_socket)),
      top_level_fiber_(LiteFiber::NewTopLevelFiber()) {}

void FiberListeningSocket::Listen(InternalCallback callback, void* arg) {
  while (true) {
    Envelope incoming_envelope;
    Status status = in_socket_->RecvEnvelope(&incoming_envelope);
    if (!status.ok()) {
      err_socket_->Send(status.message(), /*payload_secret=*/"");
      break;
    }
    FiberWrapper* fiber;
    FiberSocket* fiber_socket = FindFiberSocket(incoming_envelope.socket_id);

    if (fiber_socket == nullptr) {
      // Create a new fiber for incoming socket_id.
      auto fiber_arg = new FiberArg{
          .err_socket = err_socket_.get(),
          .callback = callback,
          .callback_arg = arg,
          .first_envelope = incoming_envelope,
          .listening_socket = this,
      };
      std::unique_ptr<FiberWrapper> new_fiber(new FiberWrapper{
          .fiber = top_level_fiber_->NewFiber(&NewChannel, fiber_arg),
          .socket_id = incoming_envelope.socket_id,
      });
      fiber = new_fiber.get();
      socket_id_to_fiber_map_[incoming_envelope.socket_id] =
          std::move(new_fiber);

      // Create a new fiber socket with above fiber.
      auto fiber_socket = std::make_unique<FiberSocket>(
          incoming_envelope.src, self_, incoming_envelope.socket_id,
          out_socket_.get(), fiber, this);
      // Set FiberArg::bidi_socket to above fiber_socket.
      fiber_arg->bidi_socket = fiber_socket.get();
      socket_id_to_fiber_socket_map_[incoming_envelope.socket_id] =
          std::move(fiber_socket);

    } else {
      fiber = fiber_socket->fiber_;
      fiber_socket->incoming_envelope_ = incoming_envelope;
      fiber_socket->incoming_envelope_available_ = true;
    }

    current_fiber_ = fiber;
    top_level_fiber_->SwitchTo(fiber->fiber.get());
    if (fiber->fiber->IsDone()) {
      socket_id_to_fiber_socket_map_.erase(fiber->socket_id);
      socket_id_to_fiber_map_.erase(fiber->socket_id);
    }
  }
}

FiberListeningSocket::FiberSocket* FiberListeningSocket::FindFiberSocket(
    const std::string& socket_id) {
  {
    auto it = socket_id_to_fiber_socket_map_.find(socket_id);
    if (it != socket_id_to_fiber_socket_map_.end()) {
      return it->second.get();
    }
  }
  {
    auto it = socket_id_to_unowned_fiber_socket_map_.find(socket_id);
    if (it != socket_id_to_unowned_fiber_socket_map_.end()) {
      return it->second;
    }
  }
  return nullptr;
}

StatusOr<std::unique_ptr<SocketInternal>> FiberListeningSocket::CreateSocket(
    const Socket::EndpointId& peer, bool require_secure) {
  // FiberListeningSocket can not create secure sockets.
  if (require_secure) {
    return Status(kInternal,
                  "FiberListeningSocket can not create a secure socket");
  }
  if (current_fiber_ == nullptr) {
    return Status(
        kFailedPrecondition,
        "CreateSocket must be called by a callback invoked by Listen");
  }

  std::string new_socket_id = RandomSocketId();
  std::unique_ptr<FiberSocket> fiber_socket = std::make_unique<FiberSocket>(
      peer, self_, new_socket_id, out_socket_.get(), current_fiber_, this);
  // This socket_id -> FiberSocket entry must be new.
  SC_CHECK(socket_id_to_unowned_fiber_socket_map_.find(new_socket_id) ==
           socket_id_to_unowned_fiber_socket_map_.end());
  socket_id_to_unowned_fiber_socket_map_[new_socket_id] = fiber_socket.get();
  return std::unique_ptr<SocketInternal>(fiber_socket.release());
}

}  // namespace wasm
}  // namespace sealed
