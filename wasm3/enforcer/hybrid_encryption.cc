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

#include "third_party/sealedcomputing/wasm3/enforcer/hybrid_encryption.h"

#include "third_party/openssl/boringssl/src/include/openssl/bn.h"
#include "third_party/openssl/boringssl/src/include/openssl/curve25519.h"
#include "third_party/openssl/boringssl/src/include/openssl/ec.h"
#include "third_party/openssl/boringssl/src/include/openssl/nid.h"
#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/crypto.h"
#include "third_party/sealedcomputing/wasm3/enforcer/crypto_internal.h"
#include "third_party/sealedcomputing/wasm3/enforcer/uefi_crypto/aes.h"
#include "third_party/sealedcomputing/wasm3/enforcer/uefi_crypto/p256.h"
#include "third_party/sealedcomputing/wasm3/logging.h"
#include "third_party/sealedcomputing/wasm3/status.h"
#include "third_party/sealedcomputing/wasm3/statusor.h"

namespace sealed {
namespace wasm {

namespace {

constexpr char kHKDFInfoX25519HybridEncryption[] =
    "HKDF info: sealed computing v0: X25519 hybrid encryption keygen";
constexpr char kHKDFInfoP256HybridEncryption[] =
    "HKDF info: sealed computing v0: P256 hybrid encryption keygen";
constexpr char kHKDFSalt[] = "HKDF salt: sealed computing v0";

// Constants associated with Tink wire format for
// EciesX25519HkdfHmacSha256Aes256Gcm ciphertexts.
// Reference: g3doc/third_party/tink/g3doc/WIRE-FORMAT.md#hybrid-encryption
// constexpr size_t kTinkPrefixLength = 5;
constexpr size_t kKemLength = 32;

constexpr size_t kP256CompressedPointLength = 33;
constexpr size_t kP256KemLength = kP256CompressedPointLength;
constexpr size_t kP256PointCoordinateLength = 32;

// `kem_bytes` is a portion of the hybrid encryption ciphertext.
StatusOr<SecretByteString> P256ECDH(const ByteString& kem_bytes,
                                    const EC_KEY* priv_key) {
  const EC_GROUP* group = EC_KEY_get0_group(priv_key);
  // Parse `kem_bytes` into a public EC_POINT.
  EC_POINT* pub_key = EC_POINT_new(group);
  if (EC_POINT_oct2point(group, pub_key, kem_bytes.data(), kP256KemLength,
                         nullptr) != 1) {
    return Status(kInvalidArgument, "bad ciphertext");
  }
  if (EC_POINT_is_on_curve(group, pub_key, nullptr) != 1) {
    return Status(kInvalidArgument, "bad ciphertext");
  }

  // Use the public EC_POINT and `priv_key` to compute shared private EC_POINT.
  EC_POINT* shared_point = EC_POINT_new(group);
  SC_CHECK_EQ(1, EC_POINT_mul(group, shared_point, nullptr, pub_key,
                              EC_KEY_get0_private_key(priv_key), nullptr));
  SC_CHECK_EQ(1, EC_POINT_is_on_curve(group, shared_point, nullptr));

  // Serialize shared EC_POINT to obtain shared secret.
  BIGNUM* shared_secret = BN_new();
  SC_CHECK_EQ(1, EC_POINT_get_affine_coordinates(
                     group, shared_point, shared_secret, nullptr, nullptr));
  SC_CHECK_GE(kP256PointCoordinateLength, BN_num_bytes(shared_secret));
  SecretByteString shared_secret_bytes(kP256PointCoordinateLength);
  SC_CHECK_SSL_OK(BN_bn2bin_padded(shared_secret_bytes.data(),
                                   kP256PointCoordinateLength, shared_secret));

  EC_POINT_free(pub_key);
  EC_POINT_free(shared_point);
  BN_free(shared_secret);
  return shared_secret_bytes;
}

}  // namespace

EciesX25519PrivateKey::EciesX25519PrivateKey(const SecretByteString& secret) {
  x25519_private_key_ =
      enforcer::Hkdf(X25519_PRIVATE_KEY_LEN, secret, kHKDFSalt,
                     kHKDFInfoX25519HybridEncryption);
  x25519_public_value_ = ByteString(X25519_PUBLIC_VALUE_LEN);
  X25519_public_from_private(x25519_public_value_.data(),
                             x25519_private_key_.data());
}

StatusOr<SecretByteString> EciesX25519PrivateKey::Decrypt(
    const std::string& ciphertext, const std::string& context_info) const {
  SecretByteString ikm(kKemLength + X25519_SHARED_KEY_LEN);
  if (ciphertext.size() < kKemLength) {
    return Status(kInvalidArgument, "bad ciphertext");
  }
  memcpy(ikm.data(), ciphertext.data(), kKemLength);
  SC_CHECK_SSL_OK(
      X25519(ikm.data() + kKemLength, x25519_private_key_.data(), ikm.data()));
  SecretByteString key = enforcer::Hkdf(uefi_crypto::kAes256KeyLength, ikm,
                                        /*salt=*/"", context_info);

  ByteString aead_ciphertext = ciphertext.substr(kKemLength);
  if (aead_ciphertext.size() <
      (uefi_crypto::kAesGcmNonceLength + uefi_crypto::kAesGcmTagLength)) {
    return Status(kInvalidArgument, "bad ciphertext");
  }
  // Note: Tink EciesX25519HkdfHmacSha256Aes256Gcm uses empty additional data.
  ByteString nonce = aead_ciphertext.substr(0, enforcer::kAesGcmNonceLength);
  ByteString enc_text = aead_ciphertext.substr(enforcer::kAesGcmNonceLength);
  return uefi_crypto::AesGcmDecrypt(key, nonce, enc_text, "");
}

ByteString EciesX25519PublicKey::Encrypt(
    const SecretByteString& plaintext, const std::string& context_info) const {
  SecretByteString private_key = RandBytes(X25519_PRIVATE_KEY_LEN);
  ByteString public_value(X25519_PUBLIC_VALUE_LEN);
  X25519_public_from_private(public_value.data(), private_key.data());
  SecretByteString shared_secret(X25519_SHARED_KEY_LEN);
  SC_CHECK_SSL_OK(X25519(shared_secret.data(), private_key.data(),
                         x25519_public_value_.data()));

  SecretByteString ikm(kKemLength + X25519_SHARED_KEY_LEN);
  memcpy(ikm.data(), public_value.data(), kKemLength);
  memcpy(ikm.data() + kKemLength, shared_secret.data(), X25519_SHARED_KEY_LEN);
  SecretByteString key = enforcer::Hkdf(uefi_crypto::kAes256KeyLength, ikm,
                                        /*salt=*/"", context_info);

  ByteString nonce = RandBytes(uefi_crypto::kAesGcmNonceLength);
  StatusOr<ByteString> ciphertext =
      uefi_crypto::AesGcmEncrypt(key, nonce, plaintext, "");
  SC_CHECK_OK(ciphertext);

  return public_value + nonce + *ciphertext;
}

EciesP256PrivateKey::EciesP256PrivateKey(const SecretByteString& secret) {
  private_key_ = uefi_crypto::DeriveP256KeyFromSecret(
      secret, kHKDFInfoP256HybridEncryption);
}

StatusOr<SecretByteString> EciesP256PrivateKey::Decrypt(
    const std::string& ciphertext, const std::string& context_info) const {
  SecretByteString ikm(kP256KemLength + kP256PointCoordinateLength);
  if (ciphertext.size() < kP256KemLength) {
    return Status(kInvalidArgument, "bad ciphertext");
  }
  memcpy(ikm.data(), ciphertext.data(), kP256KemLength);
  SC_ASSIGN_OR_RETURN(
      SecretByteString shared_secret,
      P256ECDH(ciphertext.substr(0, kP256KemLength), private_key_));
  memcpy(ikm.data() + kP256KemLength, shared_secret.data(),
         kP256PointCoordinateLength);

  SecretByteString key = enforcer::Hkdf(uefi_crypto::kAes128KeyLength, ikm,
                                        /*salt=*/"", context_info);

  ByteString aead_ciphertext = ciphertext.substr(kP256KemLength);
  if (aead_ciphertext.size() <
      (uefi_crypto::kAesGcmNonceLength + uefi_crypto::kAesGcmTagLength)) {
    return Status(kInvalidArgument, "bad ciphertext");
  }
  // Note: Tink EciesP256CompressedHkdfHmacSha256Aes128Gcm uses empty additional
  // data.
  ByteString nonce = aead_ciphertext.substr(0, enforcer::kAesGcmNonceLength);
  ByteString enc_text = aead_ciphertext.substr(enforcer::kAesGcmNonceLength);
  return uefi_crypto::AesGcmDecrypt(key, nonce, enc_text, "");
}

EciesP256PublicKey::operator ByteString() const {
  auto public_key = ByteString(kP256CompressedPointLength);
  SC_CHECK_EQ(kP256CompressedPointLength,
              EC_POINT_point2oct(group_, public_key_,
                                 POINT_CONVERSION_COMPRESSED, public_key.data(),
                                 kP256CompressedPointLength, nullptr));
  return public_key;
}

EciesP256PublicKey::operator std::string() const {
  ByteString pubkey = *this;
  return pubkey.string();
}

ByteString EciesP256PublicKey::Encrypt(const SecretByteString& plaintext,
                                       const std::string& context_info) const {
  SecretByteString private_key = RandBytes(32);
  auto ephemeral_private_key = EciesP256PrivateKey(private_key);
  auto shared_secret = P256ECDH(*this, ephemeral_private_key.private_key_);
  SC_CHECK_OK(shared_secret);

  SecretByteString ikm(kP256KemLength + kP256PointCoordinateLength);
  auto ephemeral_public_key = ephemeral_private_key.GetPublicKey();
  ByteString ephemeral_public_key_bytes = *ephemeral_public_key;
  SC_CHECK_EQ(kP256KemLength, ephemeral_public_key_bytes.size());
  memcpy(ikm.data(), ephemeral_public_key_bytes.data(), kP256KemLength);
  memcpy(ikm.data() + kP256KemLength, shared_secret->data(),
         kP256PointCoordinateLength);
  SecretByteString key = enforcer::Hkdf(uefi_crypto::kAes128KeyLength, ikm,
                                        /*salt=*/"", context_info);

  ByteString nonce = RandBytes(uefi_crypto::kAesGcmNonceLength);
  StatusOr<ByteString> ciphertext =
      uefi_crypto::AesGcmEncrypt(key, nonce, plaintext, "");
  SC_CHECK_OK(ciphertext);

  return ephemeral_public_key_bytes + nonce + *ciphertext;
}

StatusOr<std::unique_ptr<EciesP256PublicKey>> EciesP256PublicKey::Create(
    const ByteString& pubkey) {
  EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  EC_POINT* point = EC_POINT_new(group);

  if (1 !=
      EC_POINT_oct2point(group, point, pubkey.data(), pubkey.size(), nullptr)) {
    EC_GROUP_free(group);
    EC_POINT_free(point);
    return Status(kInvalidArgument, "error parsing P256 public key");
  }

  if (1 != EC_POINT_is_on_curve(group, point, nullptr)) {
    EC_GROUP_free(group);
    EC_POINT_free(point);
    return Status(kInvalidArgument, "argument not a valid P256 public key");
  }

  auto key = std::make_unique<EciesP256PublicKey>(group, point);
  EC_GROUP_free(group);
  EC_POINT_free(point);
  return key;
}

ByteString EciesP256PublicKey::GetX() const {
  BIGNUM* x = BN_new();
  SC_CHECK_EQ(1, EC_POINT_get_affine_coordinates(group_, public_key_, x,
                                                 nullptr, nullptr));
  SC_CHECK_GE(kP256PointCoordinateLength, BN_num_bytes(x));
  ByteString xbs(kP256PointCoordinateLength);
  SC_CHECK_SSL_OK(BN_bn2bin_padded(xbs.data(), kP256PointCoordinateLength, x));
  BN_free(x);
  return xbs;
}

ByteString EciesP256PublicKey::GetY() const {
  BIGNUM* y = BN_new();
  SC_CHECK_EQ(1, EC_POINT_get_affine_coordinates(group_, public_key_, nullptr,
                                                 y, nullptr));
  SC_CHECK_GE(kP256PointCoordinateLength, BN_num_bytes(y));
  ByteString ybs(kP256PointCoordinateLength);
  SC_CHECK_SSL_OK(BN_bn2bin_padded(ybs.data(), kP256PointCoordinateLength, y));
  BN_free(y);
  return ybs;
}

}  // namespace wasm
}  // namespace sealed
