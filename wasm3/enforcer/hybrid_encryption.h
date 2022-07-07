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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_HYBRID_ENCRYPTION_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_HYBRID_ENCRYPTION_H_

#include <string>

#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/statusor.h"

namespace sealed {
namespace wasm {

// Wraps an X25519 public key and provides a method to encrypt plaintexts
// to this public key.
class HybridEncryptionPublicKey {
 public:
  explicit HybridEncryptionPublicKey(const ByteString& x25519_public_value)
      : x25519_public_value_(x25519_public_value) {}

  // The resulting ciphertext is wire-format compatible with the Tink hybrid
  // encryption primitive with the EciesX25519HkdfHmacSha256Aes256Gcm format,
  // except that it does not include the 5-byte Tink prefix.
  // See g3doc/third_party/tink/g3doc/WIRE-FORMAT.md for more details.
  ByteString Encrypt(const SecretByteString& plaintext,
                     const std::string& context_info) const;

  operator ByteString() const { return x25519_public_value_; }
  operator std::string() const { return x25519_public_value_.string(); }

 private:
  ByteString x25519_public_value_;
};

// HybridEncryptionPrivateKey wraps a X25519 keypair and provides methods
// to decrypt ciphertexts encrypted to its public key.
class HybridEncryptionPrivateKey {
 public:
  // Derives the X25519 private key from `secret`.
  HybridEncryptionPrivateKey(const SecretByteString& secret);

  // Assumes the ciphertext is wire-format compatible the Tink
  // EciesX25519HkdfHmacSha256Aes256Gcm hybrid encryption primitive, except
  // that it does not include the 5-byte Tink prefix.
  StatusOr<SecretByteString> Decrypt(const std::string& ciphertext,
                                     const std::string& context_info) const;

  HybridEncryptionPublicKey GetPublicKey() const {
    return HybridEncryptionPublicKey(x25519_public_value);
  }

 private:
  SecretByteString x25519_private_key;
  ByteString x25519_public_value;
};

}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_HYBRID_ENCRYPTION_H_
