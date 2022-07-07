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

#include "third_party/sealedcomputing/wasm3/enforcer/secure_socket.h"

#include <memory>

#include "third_party/sealedcomputing/wasm3/enforcer/crypto_internal.h"
#include "third_party/sealedcomputing/wasm3/enforcer/envelope.common.h"
#include "third_party/sealedcomputing/wasm3/handshaker.h"
#include "third_party/sealedcomputing/wasm3/keyset_policies/p256_sign.h"
#include "third_party/sealedcomputing/wasm3/logging.h"
#include "third_party/sealedcomputing/wasm3/status.h"
#include "third_party/sealedcomputing/wasm3/statusor.h"

namespace sealed {
namespace wasm {

namespace {

std::string IntegerToAesGcmNonce(uint64_t n) {
  SC_CHECK(sizeof(uint64_t) <= enforcer::kAesGcmNonceLength);
  std::string s(enforcer::kAesGcmNonceLength, '\0');
  memcpy(s.data(), &n, sizeof(uint64_t));
  return s;
}

}  // namespace

std::string IntegerToAesGcmNonceForTesting(uint64_t n) {
  return IntegerToAesGcmNonce(n);
}

void SecureSocket::Send(const ByteString& payload,
                        const SecretByteString& payload_secret) {
  Envelope envelope;
  envelope.dst = base_socket_->Peer().string();
  envelope.src = base_socket_->Self().string();
  envelope.socket_id = base_socket_->GetSocketId();
  envelope.payload_type = PayloadType::PAYLOAD_TYPE_RPC_MESSAGE;
  envelope.payload = payload.string();
  envelope.session_envelope_num = session_->envelope_num;

  enforcer::AesGcm aes_gcm(session_->secrets.self_encryption_key);
  if (payload_secret.empty()) {
    envelope.encrypted_payload.clear();
  } else {
    envelope.encrypted_payload =
        aes_gcm
            .Encrypt(IntegerToAesGcmNonce(session_->envelope_num),
                     payload_secret)
            .string();
  }

  envelope.mac = enforcer::HmacSha256::Digest(session_->secrets.self_mac_secret,
                                              EncodeEnvelope(envelope))
                     .string();

  base_socket_->SendEnvelope(envelope);
  session_->envelope_num++;
}

Status SecureSocket::Recv(ByteString* payload,
                          SecretByteString* payload_secret) {
  Envelope envelope;
  SC_RETURN_IF_ERROR(base_socket_->RecvEnvelope(&envelope));

  if (envelope.session_envelope_num != session_->envelope_num) {
    return Status(kUnauthenticated, "session envelope number mismatch");
  }

  // Serialize a copy of envelope with all fields except mac.
  // The data authenticated by the mac is the serialization of an identical
  // envelope with the mac field set to empty.
  Envelope envelope_copy = envelope;
  envelope_copy.mac.clear();
  SC_RETURN_IF_ERROR(enforcer::HmacSha256(session_->secrets.peer_mac_secret)
                         .Update(EncodeEnvelope(envelope_copy))
                         .Validate(envelope.mac));

  // Decrypt encrypted_payload in envelope.
  {
    if (envelope.encrypted_payload.empty()) {
      payload_secret->clear();
    } else {
      enforcer::AesGcm aes_gcm(session_->secrets.peer_encryption_key);
      StatusOr<SecretByteString> result =
          aes_gcm.Decrypt(IntegerToAesGcmNonce(session_->envelope_num),
                          envelope.encrypted_payload);
      if (!result.ok()) {
        return Status(kUnauthenticated, "decryption failed");
      }
      *payload_secret = *result;
    }
  }
  *payload = envelope.payload;
  session_->envelope_num++;
  return Status();
}

StatusOr<std::unique_ptr<SecureSession>> CreateSecureSession(
    SocketInternal* socket, const P256Sign* self_signer) {
  // Verify self_signer is consistent with socket->Self()
  {
    std::string self_verifying_key;
    self_signer->GetVerifyingKey()->Serialize(&self_verifying_key);
    if (self_verifying_key != socket->Self()) {
      return Status(kInternal, "socket self id does not match signing key");
    }
  }

  // Create ClientHandshaker.
  std::unique_ptr<P256Verify> peer_verifying_key = P256Verify::Deserialize(
      socket->Peer().string(), kHandshakeSigningPurpose);
  ClientHandshaker client_handshaker(HandshakerOptions{
      .self_signing_key = self_signer,
      .peer_verifying_key = peer_verifying_key.get(),
  });

  // Do handshake till ClientHandshaker reaches terminal state.
  std::string outgoing_frame;
  Handshaker::Result result = client_handshaker.NextHandshakeStep(
      ClientHandshaker::InitFrame(), &outgoing_frame);
  Envelope envelope;
  envelope.dst = socket->Peer().string();
  envelope.src = socket->Self().string();
  envelope.socket_id = socket->GetSocketId();
  envelope.payload_type = PayloadType::PAYLOAD_TYPE_HANDSHAKE_REQUEST;
  envelope.payload = outgoing_frame;
  socket->SendEnvelope(envelope);
  while (!Handshaker::IsTerminalResult(result)) {
    ByteString incoming_frame;
    SecretByteString unused;
    SC_RETURN_IF_ERROR(socket->Recv(&incoming_frame, &unused));
    result = client_handshaker.NextHandshakeStep(incoming_frame.string(),
                                                 &outgoing_frame);
    // If result is COMPLETED, outgoing_frame is ClientId frame.
    // If result is ABORTED, outgoing_frame is either Abort frame or empty
    // depending on whether handshaker or peer aborted first.
    // If result is non-terminal, outgoing_frame is non-empty and needs to be
    // sent.
    // In all cases, if outgoing_frame is non-empty, send it out.
    // TODO(sidtelang): fix handshaker so that ClientHandshaker reaches non
    // terminal state after sending out CLIENT_ID: it waits for Server to
    // response to ClientId frame before reaching terminal state.
    if (!outgoing_frame.empty()) {
      socket->Send(outgoing_frame, /*payload_secret=*/"");
    }
  }

  // If most recently sent frame was non-empty, expect an empty response on
  // successful handshake.
  if (!outgoing_frame.empty()) {
    ByteString incoming_frame;
    SecretByteString incoming_payload_secret;
    SC_RETURN_IF_ERROR(socket->Recv(&incoming_frame, &incoming_payload_secret));
    // If peer handshaker sends a non-empty frame in response then the handshake
    // was not successful.
    if (!incoming_frame.empty()) {
      return Status(kInternal,
                    "client handshaker: handshake aborted by peer server");
    }
  } else {
    return Status(kInternal,
                  "client handshaker: handshake aborted by peer server");
  }

  SecureSession* session = new SecureSession();
  session->secrets = client_handshaker.GetSessionSecrets();
  return std::unique_ptr<SecureSession>(session);
}

StatusOr<std::unique_ptr<SecureSession>> AcceptSecureSession(
    Socket* socket, const std::string& first_handshake_message,
    const P256Sign* self_signer) {
  // Verify self_signer is consistent with socket->Self()
  {
    std::string self_verifying_key;
    self_signer->GetVerifyingKey()->Serialize(&self_verifying_key);
    if (self_verifying_key != socket->Self()) {
      return Status(kInternal, "socket self id does not match signing key");
    }
  }

  // Create ServerHandshaker.
  std::unique_ptr<P256Verify> peer_verifying_key = P256Verify::Deserialize(
      socket->Peer().string(), kHandshakeSigningPurpose);
  HandshakerOptions options;
  options.self_signing_key = self_signer;
  options.peer_verifying_key = peer_verifying_key.get();
  ServerHandshaker server_handshaker(options);

  // Do handshake till ServerHandshaker reaches terminal state.
  std::string outgoing_frame;
  Handshaker::Result result = server_handshaker.NextHandshakeStep(
      first_handshake_message, &outgoing_frame);
  while (!Handshaker::IsTerminalResult(result)) {
    socket->Send(outgoing_frame, /*payload_secret=*/"");
    ByteString incoming_frame;
    SecretByteString incoming_payload_secret;
    SC_RETURN_IF_ERROR(socket->Recv(&incoming_frame, &incoming_payload_secret));
    result = server_handshaker.NextHandshakeStep(incoming_frame.string(),
                                                 &outgoing_frame);
  }

  // At this point, outgoing_frame is either an abort frame or empty if
  // - the server handshaker succeeds, or
  // - the client handshaker sent an abort frame during the handshake.
  // In either case, the client is expecting it so it needs to be sent.
  socket->Send(outgoing_frame, /*payload_secret=*/"");

  if (result == Handshaker::Result::ABORTED) {
    return Status(kInternal, "handshake aborted");
  }

  SecureSession* session = new SecureSession;
  session->secrets = server_handshaker.GetSessionSecrets();
  return std::unique_ptr<SecureSession>(session);
}

}  // namespace wasm
}  // namespace sealed
