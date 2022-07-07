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

#include "third_party/sealedcomputing/wasm3/handshaker.h"

#include <cstdint>
#include <memory>

#include "third_party/openssl/boringssl/src/include/openssl/curve25519.h"
#include "third_party/sealedcomputing/wasm3/base.h"
#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/crypto.h"
#include "third_party/sealedcomputing/wasm3/enforcer/crypto_internal.h"
#include "third_party/sealedcomputing/wasm3/status.h"

namespace sealed {
namespace wasm {

using Result = Handshaker::Result;

namespace {

enum FrameType : char {
  kInit = 0,
  kClientHello,
  kServerId,
  kClientId,
  kAbort,
  kMaxValue,
};
constexpr size_t kFrameHeaderLength = sizeof(FrameType);

constexpr size_t kClientHelloRandomOffset = kFrameHeaderLength;
constexpr size_t kClientHelloRandomLength = 32;
constexpr size_t kClientHelloEndOffset =
    kClientHelloRandomOffset + kClientHelloRandomLength;

constexpr size_t kServerIdDhPublicValueOffset = kFrameHeaderLength;
constexpr size_t kServerIdDhPublicValueLength = X25519_PUBLIC_VALUE_LEN;
constexpr size_t kServerIdRandomOffset =
    kServerIdDhPublicValueOffset + kServerIdDhPublicValueLength;
constexpr size_t kServerIdRandomLength = 32;
constexpr size_t kServerIdSignatureOffset =
    kServerIdRandomOffset + kServerIdRandomLength;
constexpr size_t kServerIdSignatureLength = kSignatureLength;
constexpr size_t kServerIdEndOffset =
    kServerIdSignatureOffset + kServerIdSignatureLength;

constexpr size_t kClientIdDhPublicValueOffset = kFrameHeaderLength;
constexpr size_t kClientIdDhPublicValueLength = X25519_PUBLIC_VALUE_LEN;
constexpr size_t kClientIdRandomOffset =
    kClientIdDhPublicValueOffset + kClientIdDhPublicValueLength;
constexpr size_t kClientIdRandomLength = 32;
constexpr size_t kClientIdSignatureOffset =
    kClientIdRandomOffset + kClientIdRandomLength;
constexpr size_t kClientIdSignatureLength = kSignatureLength;
constexpr size_t kClientIdEndOffset =
    kClientIdSignatureOffset + kClientIdSignatureLength;

std::string AbortFrame() { return std::string(kFrameHeaderLength, kAbort); }

}  // namespace

std::string ClientHandshaker::InitFrame() {
  return std::string(kFrameHeaderLength, kInit);
}

std::string AbortFrameForTesting() { return AbortFrame(); }

std::string InvalidFrameForTesting() {
  std::string invalid_frame(1, '\0');
  invalid_frame[0] = kMaxValue;
  return invalid_frame;
}

X25519Key::X25519Key() {
  private_key = RandBytes(X25519_PRIVATE_KEY_LEN);
  public_value = ByteString(X25519_PUBLIC_VALUE_LEN);
  X25519_public_from_private(public_value.data(), private_key.data());
}

SecretByteString X25519Key::DeriveSharedSecret(
    const ByteString& peer_public_value) const {
  SC_CHECK_EQ(peer_public_value.size(), X25519_PUBLIC_VALUE_LEN);
  SC_CHECK_EQ(private_key.size(), X25519_PRIVATE_KEY_LEN);
  SecretByteString shared_secret(X25519_SHARED_KEY_LEN);
  SC_CHECK_SSL_OK(X25519(shared_secret.data(), private_key.data(),
                         peer_public_value.data()));
  return shared_secret;
}

void ClientHandshaker::DeriveSessionSecrets() {
  SecretByteString shared_dh_secret =
      self_dh_key_pair_->DeriveSharedSecret(peer_dh_public_value_);
  std::string common_salt = "Sealed handshake protocol v1";
  {
    std::string info = "client encryption key";
    info.append(transcript_);
    secrets_.self_encryption_key =
        enforcer::Hkdf(SessionSecrets::kEncryptionKeyLength, shared_dh_secret,
                       common_salt, info);
  }
  {
    std::string info = "server encryption key";
    info.append(transcript_);
    secrets_.peer_encryption_key =
        enforcer::Hkdf(SessionSecrets::kEncryptionKeyLength, shared_dh_secret,
                       common_salt, info);
  }
  {
    std::string info = "client mac secret";
    info.append(transcript_);
    secrets_.self_mac_secret = enforcer::Hkdf(
        SessionSecrets::kMacSecretLength, shared_dh_secret, common_salt, info);
  }
  {
    std::string info = "server mac secret";
    info.append(transcript_);
    secrets_.peer_mac_secret = enforcer::Hkdf(
        SessionSecrets::kMacSecretLength, shared_dh_secret, common_salt, info);
  }
}

void ServerHandshaker::DeriveSessionSecrets() {
  SecretByteString shared_dh_secret =
      self_dh_key_pair_->DeriveSharedSecret(peer_dh_public_value_);
  std::string common_salt = "Sealed handshake protocol v1";
  {
    std::string info = "client encryption key";
    info.append(transcript_);
    secrets_.peer_encryption_key =
        enforcer::Hkdf(SessionSecrets::kEncryptionKeyLength, shared_dh_secret,
                       common_salt, info);
  }
  {
    std::string info = "server encryption key";
    info.append(transcript_);
    secrets_.self_encryption_key =
        enforcer::Hkdf(SessionSecrets::kEncryptionKeyLength, shared_dh_secret,
                       common_salt, info);
  }
  {
    std::string info = "client mac secret";
    info.append(transcript_);
    secrets_.peer_mac_secret = enforcer::Hkdf(
        SessionSecrets::kMacSecretLength, shared_dh_secret, common_salt, info);
  }
  {
    std::string info = "server mac secret";
    info.append(transcript_);
    secrets_.self_mac_secret = enforcer::Hkdf(
        SessionSecrets::kMacSecretLength, shared_dh_secret, common_salt, info);
  }
}

Result Handshaker::GetFrameType(const std::string& incoming_frame) {
  if (incoming_frame.empty()) {
    return Result::INVALID;
  }
  FrameType frame_type = static_cast<FrameType>(incoming_frame.at(0));
  switch (frame_type) {
    case kInit:
      return Result::NEXT_INIT;
    case kClientHello:
      return Result::NEXT_CLIENT_HELLO;
    case kServerId:
      return Result::NEXT_SERVER_ID;
    case kClientId:
      return Result::NEXT_CLIENT_ID;
    case kAbort:
      return Result::ABORTED;
    default:
      return Result::INVALID;
  }
}

std::string Handshaker::ConvertFrameToString(Result result) {
  switch (result) {
    case Result::NEXT_INIT:
      return "NEXT_INIT";
    case Result::NEXT_CLIENT_HELLO:
      return "NEXT_CLIENT_HELLO";
    case Result::NEXT_SERVER_ID:
      return "NEXT_SERVER_ID";
    case Result::NEXT_CLIENT_ID:
      return "NEXT_CLIENT_ID";
    case Result::ABORTED:
      return "ABORTED";
    default:
      return "INVALID";
  }
}

std::string ClientHandshaker::HandleInit() {
  if (result_ != Handshaker::Result::NEXT_INIT) {
    result_ = Handshaker::Result::ABORTED;
    return AbortFrame();
  }
  // Initialize ClientHello frame and add header.
  std::string client_hello_frame;
  client_hello_frame.resize(kClientHelloEndOffset);
  client_hello_frame[0] = kClientHello;

  // Add client nonce.
  auto client_nonce = RandBytes(kClientHelloRandomLength);
  memcpy(client_hello_frame.data() + kClientHelloRandomOffset,
         client_nonce.data(), client_nonce.size());

  // Update transcript and return ClientHello frame.
  transcript_.append(client_hello_frame);
  result_ = Handshaker::Result::NEXT_SERVER_ID;
  return client_hello_frame;
}

std::string ServerHandshaker::HandleClientHello(
    const std::string& client_hello_frame) {
  if (result_ != Handshaker::Result::NEXT_CLIENT_HELLO) {
    result_ = Handshaker::Result::ABORTED;
    return AbortFrame();
  }
  // Validate ClientHello frame length and add to transcript.
  if (client_hello_frame.size() != kClientHelloEndOffset) {
    result_ = Handshaker::Result::ABORTED;
    return AbortFrame();
  }
  transcript_.append(client_hello_frame);

  // Initialze ServerId frame and add header.
  std::string server_id_frame;
  server_id_frame.resize(kServerIdEndOffset);
  server_id_frame[0] = kServerId;

  // Add server DH public value.
  self_dh_key_pair_ = std::make_unique<X25519Key>();
  server_id_frame.replace(kServerIdDhPublicValueOffset,
                          kServerIdDhPublicValueLength,
                          self_dh_key_pair_->public_value.string());

  // Add server nonce.
  ByteString server_nonce = RandBytes(kServerIdRandomLength);
  memcpy(server_id_frame.data() + kServerIdRandomOffset, server_nonce.data(),
         server_nonce.size());

  // Add server signature on partial transcript frame and update transcript.
  transcript_.append(server_id_frame.substr(0, kServerIdSignatureOffset));
  std::string signature;
  {
    if (!self_signing_key_->Sign(transcript_, &signature)) {
      result_ = Handshaker::Result::ABORTED;
      return AbortFrame();
    }
  }
  server_id_frame.replace(kServerIdSignatureOffset, kServerIdSignatureLength,
                          signature);
  transcript_.append(server_id_frame.substr(kServerIdSignatureOffset,
                                            kServerIdSignatureLength));
  result_ = Handshaker::Result::NEXT_CLIENT_ID;
  return server_id_frame;
}

std::string ClientHandshaker::HandleServerId(
    const std::string& server_id_frame) {
  if (result_ != Handshaker::Result::NEXT_SERVER_ID) {
    result_ = Handshaker::Result::ABORTED;
    return AbortFrame();
  }
  // Validate ServerId frame and update transcript.
  transcript_.append(server_id_frame.substr(0, kServerIdSignatureOffset));
  if (!peer_verifying_key_->Verify(
          transcript_, server_id_frame.substr(kServerIdSignatureOffset,
                                              kServerIdSignatureLength))) {
    result_ = Handshaker::Result::ABORTED;
    return AbortFrame();
  }
  transcript_.append(server_id_frame.substr(kServerIdSignatureOffset,
                                            kServerIdSignatureLength));
  peer_dh_public_value_ = server_id_frame.substr(kServerIdDhPublicValueOffset,
                                                 kServerIdDhPublicValueLength);

  // Allocate ClientId frame and add header.
  std::string client_id_frame;
  client_id_frame.resize(kClientIdEndOffset);
  client_id_frame[0] = kClientId;

  // Add client DH public value.
  self_dh_key_pair_ = std::make_unique<X25519Key>();
  client_id_frame.replace(kClientIdDhPublicValueOffset,
                          kClientIdDhPublicValueLength,
                          self_dh_key_pair_->public_value.string());

  // Update transcript and generate signature.
  transcript_.append(client_id_frame.substr(0, kClientIdSignatureOffset));
  std::string signature;
  {
    if (!self_signing_key_->Sign(transcript_, &signature)) {
      result_ = Handshaker::Result::ABORTED;
      return AbortFrame();
    }
  }
  client_id_frame.replace(kClientIdSignatureOffset, kClientIdSignatureLength,
                          signature);
  transcript_.append(client_id_frame.substr(kClientIdSignatureOffset,
                                            kClientIdSignatureLength));

  // Change result to COMPLETED, derive secrets and return ClientId frame.
  DeriveSessionSecrets();
  result_ = Handshaker::Result::COMPLETED;
  return client_id_frame;
}

std::string ServerHandshaker::HandleClientId(
    const std::string& client_id_frame) {
  if (result_ != Handshaker::Result::NEXT_CLIENT_ID) {
    result_ = Handshaker::Result::ABORTED;
    return AbortFrame();
  }
  // Validate ClientId frame and update transcript.
  transcript_.append(client_id_frame.substr(0, kClientIdSignatureOffset));
  if (!peer_verifying_key_->Verify(
          transcript_, client_id_frame.substr(kClientIdSignatureOffset,
                                              kClientIdSignatureLength))) {
    result_ = Handshaker::Result::ABORTED;
    return AbortFrame();
  }
  transcript_.append(client_id_frame.substr(kClientIdSignatureOffset,
                                            kClientIdSignatureLength));
  peer_dh_public_value_ = client_id_frame.substr(kClientIdDhPublicValueOffset,
                                                 kClientIdDhPublicValueLength);

  // Change result to COMPLETED and derive secrets.
  DeriveSessionSecrets();
  result_ = Handshaker::Result::COMPLETED;
  return "";
}

Result ClientHandshaker::NextHandshakeStep(const std::string& incoming_bytes,
                                           std::string* outgoing_bytes) {
  std::string incoming_frame = incoming_bytes;

  if (incoming_bytes.empty()) {
    // Consider this the init step.
    incoming_frame = InitFrame();
  }
  FrameType frame_type = static_cast<FrameType>(incoming_frame.at(0));
  switch (frame_type) {
    case kInit:
      *outgoing_bytes = HandleInit();
      break;
    case kServerId:
      *outgoing_bytes = HandleServerId(incoming_frame);
      break;
    case kAbort:
      result_ = Handshaker::Result::ABORTED;
      outgoing_bytes->clear();
      break;
    default:
      result_ = Handshaker::Result::ABORTED;
      *outgoing_bytes = AbortFrame();
  }
  return result_;
}

Result ServerHandshaker::NextHandshakeStep(const std::string& incoming_bytes,
                                           std::string* outgoing_bytes) {
  if (incoming_bytes.size() < kFrameHeaderLength) {
    *outgoing_bytes = AbortFrame();
    return Handshaker::Result::ABORTED;
  }
  FrameType frame_type = static_cast<FrameType>(incoming_bytes.at(0));
  switch (frame_type) {
    case kClientHello:
      *outgoing_bytes = HandleClientHello(incoming_bytes);
      break;
    case kClientId:
      *outgoing_bytes = HandleClientId(incoming_bytes);
      break;
    case kAbort:
      result_ = Handshaker::Result::ABORTED;
      outgoing_bytes->clear();
      break;
    default:
      result_ = Handshaker::Result::ABORTED;
      *outgoing_bytes = AbortFrame();
  }
  return result_;
}

bool Handshaker::IsAbortFrame(const std::string& incoming_bytes) {
  if (incoming_bytes.empty()) {
    return false;
  }
  FrameType frame_type = static_cast<FrameType>(incoming_bytes.at(0));
  return frame_type == kAbort;
}

}  // namespace wasm
}  // namespace sealed
