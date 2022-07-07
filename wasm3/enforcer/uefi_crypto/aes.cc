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

// Test AES-GCM APIs on Nanolibc.  This test runs both as a google3 test, and as
// a manually run test inside the UEFI enclave.

#include "third_party/sealedcomputing/wasm3/enforcer/uefi_crypto/aes.h"

#include <cstdint>
#include <cstdio>
#include <cstring>

#include "third_party/openssl/boringssl/src/include/openssl/aead.h"
#include "third_party/openssl/boringssl/src/include/openssl/aes.h"
#include "third_party/openssl/boringssl/src/include/openssl/cipher.h"
#include "third_party/openssl/boringssl/src/include/openssl/mem.h"
#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/enforcer/uefi_crypto/init_crypto.h"
#include "third_party/sealedcomputing/wasm3/statusor.h"

namespace sealed {
namespace wasm {
namespace uefi_crypto {

void AesEncryptBlock(const ByteString& key, const ByteString& in,
                     ByteString* out) {
  if (!global_initialized) {
    InitializeCryptoLib();
  }
  SC_CHECK_EQ(in.size(), uefi_crypto::kAesBlockSize);
  if (out->size() != uefi_crypto::kAesBlockSize) {
    *out = ByteString(uefi_crypto::kAesBlockSize);
  }
  SC_CHECK(key.size() == kAes128KeyLength || key.size() == kAes256KeyLength);
  AES_KEY encrypt_key;
  SC_CHECK_SSL_AES_OK(
      AES_set_encrypt_key(key.data(), 8 * kAes128KeyLength, &encrypt_key));
  AES_encrypt(in.data(), out->data(), &encrypt_key);
}

void AesDecryptBlock(const ByteString& key, const ByteString& in,
                     SecretByteString* out) {
  if (!global_initialized) {
    InitializeCryptoLib();
  }
  SC_CHECK_EQ(in.size(), uefi_crypto::kAesBlockSize);
  if (out->size() != uefi_crypto::kAesBlockSize) {
    *out = SecretByteString(uefi_crypto::kAesBlockSize);
  }
  SC_CHECK(key.size() == kAes128KeyLength || key.size() == kAes256KeyLength);
  AES_KEY decrypt_key;
  SC_CHECK_SSL_AES_OK(
      AES_set_decrypt_key(key.data(), 8 * kAes128KeyLength, &decrypt_key));
  AES_decrypt(in.data(), out->data(), &decrypt_key);
}

StatusOr<ByteString> AesGcmEncrypt(const ByteString& key,
                                   const ByteString& nonce,
                                   const SecretByteString& plaintext,
                                   const ByteString& associated_data) {
  if (!global_initialized) {
    InitializeCryptoLib();
  }
  if (key.size() != kAes128KeyLength && key.size() != kAes256KeyLength) {
    // TODO: once ByteString has a method for conversion to decimal, report the
    // actual length.
    return Status(kInvalidArgument, "Invalid key length");
  }
  if (nonce.size() != kAesGcmNonceLength) {
    return Status(kInvalidArgument, "Invalid nonce length");
  }
  if (plaintext.empty()) {
    return Status(kInvalidArgument, "No plaintext to encrypt");
  }
  const EVP_CIPHER* cipher;
  if (key.size() == kAes128KeyLength) {
    cipher = EVP_aes_128_gcm();
  } else {
    cipher = EVP_aes_256_gcm();
  }
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, cipher, NULL, key.data(), nonce.data());
  int len;
  if (!associated_data.empty()) {
    EVP_EncryptUpdate(ctx, NULL, &len, associated_data.data(),
                      associated_data.size());
  }
  ByteString ciphertext(plaintext.size() + kAesGcmTagLength);
  EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(),
                    plaintext.size());
  if (!EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) {
    return Status(kInvalidArgument, "Failed to encrypt message");
  }
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kAesGcmTagLength,
                      ciphertext.data() + plaintext.size());
  EVP_CIPHER_CTX_free(ctx);
  return ciphertext;
}

StatusOr<SecretByteString> AesGcmDecrypt(const ByteString& key,
                                         const ByteString& nonce,
                                         const ByteString& ciphertext,
                                         const ByteString& associated_data) {
  if (!global_initialized) {
    InitializeCryptoLib();
  }
  int len;
  if (key.size() != kAes128KeyLength && key.size() != kAes256KeyLength) {
    return Status(kInvalidArgument, "Invalid key length");
  }
  if (nonce.size() != kAesGcmNonceLength) {
    return Status(kInvalidArgument, "Invalid nonce length");
  }
  if (ciphertext.size() <= kAesGcmTagLength) {
    return Status(kInvalidArgument, "Ciphertext too short");
  }
  size_t plaintext_len = ciphertext.size() - kAesGcmTagLength;
  const uint8_t* tag = ciphertext.data() + ciphertext.size() - kAesGcmTagLength;
  const EVP_CIPHER* cipher;
  if (key.size() == kAes128KeyLength) {
    cipher = EVP_aes_128_gcm();
  } else {
    cipher = EVP_aes_256_gcm();
  }
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL);
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, kAesGcmTagLength,
                      const_cast<uint8_t*>(tag));
  EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), nonce.data());
  if (!associated_data.empty()) {
    EVP_DecryptUpdate(ctx, NULL, &len, associated_data.data(),
                      associated_data.size());
  }
  SecretByteString plaintext(plaintext_len);
  EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(),
                    plaintext_len);
  if (!EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) {
    EVP_CIPHER_CTX_free(ctx);
    return Status(kInvalidArgument, "Decryption failed");
  }
  EVP_CIPHER_CTX_free(ctx);
  return plaintext;
}

}  // namespace uefi_crypto
}  // namespace wasm
}  // namespace sealed
