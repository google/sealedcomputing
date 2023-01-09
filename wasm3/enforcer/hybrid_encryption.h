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

#include <memory>
#include <string>

#include "third_party/openssl/boringssl/src/include/openssl/ec.h"
#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/statusor.h"

namespace sealed {
namespace wasm {

// Abstract interface for hybrid encryption public keys.
class HybridEncryptionPublicKey {
 public:
  virtual ~HybridEncryptionPublicKey() = default;

  virtual ByteString Encrypt(const SecretByteString& plaintext,
                             const std::string& context_info) const = 0;

  // Implementations of this interface must define a serialization format for
  // the hybrid encryption public key.
  virtual operator ByteString() const = 0;
  virtual operator std::string() const = 0;
};

// Abstract interface for hybrid encryption private keys.
class HybridEncryptionPrivateKey {
 public:
  virtual ~HybridEncryptionPrivateKey() = default;

  virtual StatusOr<SecretByteString> Decrypt(
      const std::string& ciphertext, const std::string& context_info) const = 0;

  virtual std::unique_ptr<HybridEncryptionPublicKey> GetPublicKey() const = 0;
};

// Wraps an X25519 public key and provides a method to encrypt plaintexts
// to this public key.
class EciesX25519PublicKey : public HybridEncryptionPublicKey {
 public:
  explicit EciesX25519PublicKey(const ByteString& x25519_public_value)
      : x25519_public_value_(x25519_public_value) {}

  // The resulting ciphertext is wire-format compatible with the Tink hybrid
  // encryption primitive with the EciesX25519HkdfHmacSha256Aes256Gcm format,
  // except that it does not include the 5-byte Tink prefix.
  // See g3doc/third_party/tink/g3doc/WIRE-FORMAT.md for more details.
  ByteString Encrypt(const SecretByteString& plaintext,
                     const std::string& context_info) const override;

  operator ByteString() const override { return x25519_public_value_; }
  operator std::string() const override {
    return x25519_public_value_.string();
  }

 private:
  ByteString x25519_public_value_;
};

// HybridEncryptionPrivateKey wraps a X25519 keypair and provides methods
// to decrypt ciphertexts encrypted to its public key.
class EciesX25519PrivateKey : public HybridEncryptionPrivateKey {
 public:
  // Derives the X25519 private key from `secret`.
  EciesX25519PrivateKey(const SecretByteString& secret);

  // Assumes the ciphertext is wire-format compatible the Tink
  // EciesX25519HkdfHmacSha256Aes256Gcm hybrid encryption primitive, except
  // that it does not include the 5-byte Tink prefix.
  StatusOr<SecretByteString> Decrypt(
      const std::string& ciphertext,
      const std::string& context_info) const override;

  std::unique_ptr<HybridEncryptionPublicKey> GetPublicKey() const override {
    return std::unique_ptr<HybridEncryptionPublicKey>(
        new EciesX25519PublicKey(x25519_public_value_));
  }

 private:
  SecretByteString x25519_private_key_;
  ByteString x25519_public_value_;
};

// HybridEncryptionPublicKey implementation that is equivalent to and compatible
// with Tink Hybrid Encryption format:
// EciesP256CompressedHkdfHmacSha256Aes128Gcm
class EciesP256PublicKey : public HybridEncryptionPublicKey {
 public:
  EciesP256PublicKey(const EC_GROUP* group, const EC_POINT* src) {
    group_ = EC_GROUP_dup(group);
    public_key_ = EC_POINT_dup(src, group);
  }

  // Accepts the EC point serialized in X9.62 format.
  static StatusOr<std::unique_ptr<EciesP256PublicKey>> Create(
      const ByteString& serialized_pubkey);

  ~EciesP256PublicKey() {
    EC_GROUP_free(group_);
    EC_POINT_free(public_key_);
  }

  ByteString Encrypt(const SecretByteString& plaintext,
                     const std::string& context_info) const override;

  // Returns the EC point serialized in the X9.62 compressed point format.
  operator ByteString() const override;
  operator std::string() const override;
  static constexpr size_t kPublicKeyLength = 33;

  ByteString GetX() const;
  ByteString GetY() const;

 private:
  EC_GROUP* group_;
  EC_POINT* public_key_;
};

// HybridEncryptionPrivateKey implementation that is equivalent to and
// compatible with Tink Hybrid Encryption format:
// EciesP256CompressedHkdfHmacSha256Aes128Gcm
class EciesP256PrivateKey : public HybridEncryptionPrivateKey {
 public:
  // Derives the underlying private key from `secret`.
  EciesP256PrivateKey(const SecretByteString& secret);
  ~EciesP256PrivateKey() { EC_KEY_free(private_key_); }

  StatusOr<SecretByteString> Decrypt(
      const std::string& ciphertext,
      const std::string& context_info) const override;

  std::unique_ptr<HybridEncryptionPublicKey> GetPublicKey() const override {
    return std::unique_ptr<HybridEncryptionPublicKey>(new EciesP256PublicKey(
        EC_KEY_get0_group(private_key_), EC_KEY_get0_public_key(private_key_)));
  }

 private:
  EC_KEY* private_key_;
  friend class EciesP256PublicKey;
};

}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_HYBRID_ENCRYPTION_H_
