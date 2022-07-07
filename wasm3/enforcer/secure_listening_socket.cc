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

#include "third_party/sealedcomputing/wasm3/enforcer/secure_listening_socket.h"

#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/enforcer/secure_socket.h"
#include "third_party/sealedcomputing/wasm3/enforcer/socket_internal.h"
#include "third_party/sealedcomputing/wasm3/handshaker.h"
#include "third_party/sealedcomputing/wasm3/keyset_policies/p256_sign.h"
#include "third_party/sealedcomputing/wasm3/logging.h"
#include "third_party/sealedcomputing/wasm3/socket.h"
#include "third_party/sealedcomputing/wasm3/statusor.h"

namespace sealed {
namespace wasm {
namespace {

// Used internally only to verify and decrypt the first message on a secure
// socket sent over an existing session. Only implements the `RecvEnvelope`
// method.
class BufferedSocketInternal : public SocketInternal {
 public:
  BufferedSocketInternal(const Envelope& envelope) : envelope_(envelope) {}

  void SendEnvelope(const Envelope&) override {
    SC_PANIC() << "should not be called";
  }
  void Send(const ByteString&, const SecretByteString&) override {
    SC_PANIC() << "should not be called";
  }
  Status Recv(ByteString* payload, SecretByteString* payload_secret) override {
    (void)payload;
    (void)payload_secret;
    SC_PANIC() << "should not be called";
    return Status();
  }
  Status RecvEnvelope(Envelope* envelope) override {
    *envelope = envelope_;
    return Status();
  }
  bool IsSecure() const override {
    SC_PANIC() << "should not be called";
    return false;
  }
  EndpointId Peer() const override {
    SC_PANIC() << "should not be called";
    return "";
  }
  EndpointId Self() const override {
    SC_PANIC() << "should not be called";
    return "";
  }
  std::string GetSocketId() const override {
    SC_PANIC() << "should not be called";
    return "";
  }

 private:
  const Envelope envelope_;
};

// Wraps a user-supplied callback and callback args additionally with a pointer
// to the `SecureListeningSocket` instance that invokes this callback.
struct InternalCallbackArgs {
  void* user_supplied_args;
  ListeningSocket::Callback user_supplied_callback;
  SecureListeningSocket* secure_listening_socket;
};

// Returns a new `SecureSocket` instance after continuing to establish a new
// secure session, initiated by `first_message`, using `bidi_socket` to interact
// with the peer. The newly created secure session is added to the given
// `secure_listening_socket` instance.
// Also, reads in the first `message` and `message_secret` sent over the newly
// created secure socket.
StatusOr<std::unique_ptr<SecureSocket>> NewSecureSocketWithNewSecureSession(
    const Envelope& first_envelope,
    SecureListeningSocket* secure_listening_socket, SocketInternal* bidi_socket,
    const P256Sign* self_signer, ByteString* message,
    SecretByteString* message_secret) {
  SC_ASSIGN_OR_RETURN(
      std::unique_ptr<SecureSession> secure_session,
      AcceptSecureSession(bidi_socket, first_envelope.payload, self_signer));

  auto server_secure_socket =
      std::make_unique<SecureSocket>(bidi_socket, secure_session.get());
  SC_RETURN_IF_ERROR(server_secure_socket->Recv(message, message_secret));

  Socket::EndpointId peer = bidi_socket->Peer();
  secure_listening_socket->AddSecureSession(peer, std::move(secure_session));
  return std::move(server_secure_socket);
}

// Returns a new `SecureSocket` instance using an existing secure session.
// Also reads in the first `message` and `message_secret` sent in
// `first_envelope`.
StatusOr<std::unique_ptr<SecureSocket>>
NewSecureSocketWithExistingSecureSession(const Envelope& first_envelope,
                                         SocketInternal* bidi_socket,
                                         SecureSession* existing_session,
                                         ByteString* message,
                                         SecretByteString* message_secret) {
  // We create a temporary secure socket first to verify and decrypt
  // `first_envelope` contents. The base socket for this temporary secure
  // socket is a `BufferedSocketInternal` instance.
  auto tmp_base_socket = BufferedSocketInternal(first_envelope);
  auto tmp_secure_socket = SecureSocket(&tmp_base_socket, existing_session);
  SC_RETURN_IF_ERROR(tmp_secure_socket.Recv(message, message_secret));

  // Return a new `SecureSocket` instance with `bidi_socket` as base socket.
  return std::make_unique<SecureSocket>(bidi_socket, existing_session);
}

void InternalCallback(void* arg, const Envelope& first_envelope,
                      SocketInternal* bidi_socket, Socket* err_socket,
                      ListeningSocketInternal* listening_socket) {
  InternalCallbackArgs* args = static_cast<InternalCallbackArgs*>(arg);

  // If `first_envelope` has a mac then it is being sent over a secure session.
  // If a session exists with the peer sending `first_envelope` then create
  // a new secure socket with the existing session and invoke the user-supplied
  // callback.
  SecureSession* existing_session =
      args->secure_listening_socket->GetSecureSession(first_envelope.src);
  if (existing_session != nullptr && !first_envelope.mac.empty()) {
    ByteString message;
    SecretByteString message_secret;
    StatusOr<std::unique_ptr<SecureSocket>> secure_socket =
        NewSecureSocketWithExistingSecureSession(first_envelope, bidi_socket,
                                                 existing_session, &message,
                                                 &message_secret);
    if (!secure_socket.ok()) {
      err_socket->Send(secure_socket.message(), /*payload_secret=*/"");
      return;
    }
    args->user_supplied_callback(args->user_supplied_args, message,
                                 message_secret, secure_socket->get(),
                                 err_socket, args->secure_listening_socket);
    return;
  }

  // If payload of `first_envelope` is the first handshake frame
  // (i.e. ClientHello) then do the server-side handshake.
  // On success,
  // - create a SecureSocket to provide to the user supplied callback
  // - read in `message`, `message_secret` from the newly created
  //   SecureSocket
  // - call the user supplied callback
  // On failure, write to err_socket the Status describing the failure.
  P256Sign* self_signer = args->secure_listening_socket->GetSelfSigner();
  if (self_signer != nullptr &&
      first_envelope.payload_type ==
          PayloadType::PAYLOAD_TYPE_HANDSHAKE_REQUEST &&
      Handshaker::GetFrameType(first_envelope.payload) ==
          Handshaker::Result::NEXT_CLIENT_HELLO) {
    ByteString message;
    SecretByteString message_secret;
    StatusOr<std::unique_ptr<SecureSocket>> secure_socket =
        NewSecureSocketWithNewSecureSession(
            first_envelope, args->secure_listening_socket, bidi_socket,
            self_signer, &message, &message_secret);
    if (!secure_socket.ok()) {
      err_socket->Send(secure_socket.message(), /*payload_secret=*/"");
      return;
    }

    args->user_supplied_callback(args->user_supplied_args, message,
                                 message_secret, secure_socket->get(),
                                 err_socket, args->secure_listening_socket);
    return;
  }

  // If neither `first_message` is being sent over a secure session nor is it
  // attempting to establish a new secure session, then forward it as-is to
  // the user-supplied callback, which uses the insecure socket to
  // subsequently exchange messages with the peer.
  args->user_supplied_callback(args->user_supplied_args, first_envelope.payload,
                               /*first_message_secret=*/"", bidi_socket,
                               err_socket, args->secure_listening_socket);
}

}  // namespace

SecureListeningSocket::SecureListeningSocket(
    std::unique_ptr<ListeningSocketInternal> base_listening_socket)
    : self_signer_(nullptr),
      base_listening_socket_(std::move(base_listening_socket)) {}

SecureListeningSocket::SecureSocketInternal::SecureSocketInternal(
    SocketInternal* base_socket, SecureSession* session,
    SecureListeningSocket* creator_listening_socket)
    : SecureSocket(base_socket, session),
      creator_listening_socket_(creator_listening_socket),
      socket_id_(base_socket->GetSocketId()) {}

SecureListeningSocket::SecureSocketInternal::~SecureSocketInternal() {
  creator_listening_socket_->socket_id_to_base_socket_map_.erase(socket_id_);
}

void SecureListeningSocket::Listen(Callback callback, void* arg) {
  auto internal_callback_args =
      std::unique_ptr<InternalCallbackArgs>(new InternalCallbackArgs{
          .user_supplied_args = arg,
          .user_supplied_callback = callback,
          .secure_listening_socket = this,
      });
  base_listening_socket_->Listen(&InternalCallback,
                                 internal_callback_args.get());
}

StatusOr<std::unique_ptr<Socket>> SecureListeningSocket::CreateSocket(
    const Socket::EndpointId& peer, bool require_secure) {
  std::unique_ptr<SocketInternal> base_socket;
  SC_ASSIGN_OR_RETURN(base_socket,
                      base_listening_socket_->CreateSocket(peer, false));
  if (!require_secure) {
    return std::unique_ptr<Socket>(base_socket.release());
  }

  // If SetSigner has not been called, return an error.
  if (self_signer_ == nullptr) {
    return Status(kInternal,
                  "SecureListeningSocket can not create secure socket before "
                  "SetSelfSigner is called");
  }

  // Locate secure session with peer, creating a new one if it does not exist.
  SecureSession* secure_session;
  auto it = peer_to_secure_session_map_.find(peer.string());
  if (it == peer_to_secure_session_map_.end()) {
    std::unique_ptr<SecureSession> new_secure_session;
    SC_ASSIGN_OR_RETURN(new_secure_session,
                        CreateSecureSession(base_socket.get(), self_signer_));
    secure_session = new_secure_session.get();
    AddSecureSession(peer, std::move(new_secure_session));
  } else {
    secure_session = it->second.get();
  }

  // Create a new secure socket.
  auto secure_socket = std::make_unique<SecureSocketInternal>(
      base_socket.get(), secure_session, this);

  socket_id_to_base_socket_map_[base_socket->GetSocketId()] =
      std::move(base_socket);
  return std::unique_ptr<Socket>(secure_socket.release());
}

SecureSession* SecureListeningSocket::GetSecureSession(
    const Socket::EndpointId& peer) const {
  auto it = peer_to_secure_session_map_.find(peer.string());
  if (it == peer_to_secure_session_map_.end()) {
    return nullptr;
  } else {
    return it->second.get();
  }
}

}  // namespace wasm
}  // namespace sealed
