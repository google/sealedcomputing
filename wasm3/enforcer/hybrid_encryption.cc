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

#include "third_party/openssl/boringssl/src/include/openssl/curve25519.h"
#include "third_party/sealedcomputing/wasm3/crypto.h"
#include "third_party/sealedcomputing/wasm3/enforcer/crypto_internal.h"
#include "third_party/sealedcomputing/wasm3/enforcer/uefi_crypto/aes.h"
#include "third_party/sealedcomputing/wasm3/status.h"

namespace sealed {
namespace wasm {

namespace {

constexpr char kHKDFInfoHybridEncryption[] =
    "HKDF info: sealed computing v0: hybrid encryption keygen";
constexpr char kHKDFSalt[] = "HKDF salt: sealed computing v0";

// Constants associated with Tink wire format for
// EciesX25519HkdfHmacSha256Aes256Gcm ciphertexts.
// Reference: g3doc/third_party/tink/g3doc/WIRE-FORMAT.md#hybrid-encryption
// constexpr size_t kTinkPrefixLength = 5;
constexpr size_t kKemLength = 32;

}  // namespace

HybridEncryptionPrivateKey::HybridEncryptionPrivateKey(
    const SecretByteString& secret) {
  x25519_private_key = enforcer::Hkdf(X25519_PRIVATE_KEY_LEN, secret, kHKDFSalt,
                                      kHKDFInfoHybridEncryption);
  x25519_public_value = ByteString(X25519_PUBLIC_VALUE_LEN);
  X25519_public_from_private(x25519_public_value.data(),
                             x25519_private_key.data());
}

StatusOr<SecretByteString> HybridEncryptionPrivateKey::Decrypt(
    const std::string& ciphertext, const std::string& context_info) const {
  SecretByteString ikm(kKemLength + X25519_SHARED_KEY_LEN);
  if (ciphertext.size() < kKemLength) {
    return Status(kInvalidArgument, "bad ciphertext");
  }
  memcpy(ikm.data(), ciphertext.data(), kKemLength);
  SC_CHECK_SSL_OK(
      X25519(ikm.data() + kKemLength, x25519_private_key.data(), ikm.data()));
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

ByteString HybridEncryptionPublicKey::Encrypt(
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

}  // namespace wasm
}  // namespace sealed
