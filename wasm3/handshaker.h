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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_HANDSHAKER_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_HANDSHAKER_H_

#include <cstdint>
#include <memory>
#include <string>

#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/keyset_policies/public_key_sign.h"
#include "third_party/sealedcomputing/wasm3/keyset_policies/public_key_verify.h"
#include "third_party/sealedcomputing/wasm3/status.h"

namespace sealed {
namespace wasm {

const char kHandshakeSigningPurpose[] = "Sealed Computing Handshake v1 Signing";

struct HandshakerOptions {
  const PublicKeySign* self_signing_key;
  const PublicKeyVerify* peer_verifying_key;
};

struct SessionSecrets {
  static constexpr size_t kEncryptionKeyLength = 16;
  static constexpr size_t kMacSecretLength = 16;
  SecretByteString self_encryption_key;
  SecretByteString peer_encryption_key;
  SecretByteString self_mac_secret;
  SecretByteString peer_mac_secret;
};

// Contains keys and methods for X25519 key exchange.
struct X25519Key {
  X25519Key();
  SecretByteString DeriveSharedSecret(
      const ByteString& peer_public_value) const;

  ByteString public_value;
  SecretByteString private_key;
};

// Handshaker implements a simplification of the TLS 1.3 handshake protocol for
// use by sealed identities to establish shared session secrets for
// authenticated and encrypted (for fields marked as secret in the sealed RPC
// interface definition) sessions.
class Handshaker {
 public:
  // Result of handshake step.
  enum class Result {
    // NEXT_* values represent a handshake in progress, describing the next
    // incoming frame expected.
    INVALID = 0,
    NEXT_INIT,
    NEXT_CLIENT_HELLO,
    NEXT_SERVER_ID,
    NEXT_CLIENT_ID,
    // Terminal states.
    COMPLETED,
    ABORTED,
  };
  static inline bool IsTerminalResult(Result result) {
    return (result == Result::COMPLETED || result == Result::ABORTED);
  }
  // Returns the type of frame described as the Result value that expects it.
  static Result GetFrameType(const std::string& incoming_frame);

  // Returns a human-readable string of `result`.
  static std::string ConvertFrameToString(Result result);

  Handshaker(const HandshakerOptions& options)
      : self_signing_key_(options.self_signing_key),
        peer_verifying_key_(options.peer_verifying_key) {}
  virtual ~Handshaker() = default;

  // Performs the next handshake step for this handshaker.
  //
  // If a handshake step was completed successfully without completing the
  // handshake, returns a result of the kind `NEXT_*`.
  // If the handshake was completed successfully, returns COMPLETED.
  // If the handshake was aborted, returns ABORTED.
  virtual Result NextHandshakeStep(const std::string& incoming_bytes,
                                   std::string* outgoing_bytes) = 0;

  // Returns shared session secrets (passing ownership to the caller). Requires
  // handshake to have been completed. If the handshake has not yet completed,
  // returned SessionSecrets is empty.
  SessionSecrets GetSessionSecrets() { return std::move(secrets_); }

  Result GetResult() const { return result_; }

  static bool IsAbortFrame(const std::string& incoming_bytes);

 protected:
  virtual void DeriveSessionSecrets() = 0;

  std::string transcript_;
  Result result_;
  const PublicKeySign* self_signing_key_;
  const PublicKeyVerify* peer_verifying_key_;
  SessionSecrets secrets_;

  std::unique_ptr<X25519Key> self_dh_key_pair_;
  std::string peer_dh_public_value_;
};

class ClientHandshaker : public Handshaker {
 public:
  explicit ClientHandshaker(const HandshakerOptions& options)
      : Handshaker(options) {
    result_ = Handshaker::Result::NEXT_INIT;
  }
  Result NextHandshakeStep(const std::string& incoming_bytes,
                           std::string* outgoing_bytes) override;

  static std::string InitFrame();

 private:
  void DeriveSessionSecrets() override;
  std::string HandleInit();
  std::string HandleServerId(const std::string& server_id_frame);
};

class ServerHandshaker : public Handshaker {
 public:
  explicit ServerHandshaker(const HandshakerOptions& options)
      : Handshaker(options) {
    result_ = Handshaker::Result::NEXT_CLIENT_HELLO;
  }
  Result NextHandshakeStep(const std::string& incoming_bytes,
                           std::string* outgoing_bytes) override;

 private:
  void DeriveSessionSecrets() override;
  std::string HandleClientHello(const std::string& client_hello_frame);
  std::string HandleClientId(const std::string& client_id_frame);
};

// Returns an abort frame. Used for testing only.
std::string AbortFrameForTesting();

// Returns an invalid, non-empty frame. Used for testing only.
std::string InvalidFrameForTesting();

}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_HANDSHAKER_H_
