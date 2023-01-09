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

#include "third_party/sealedcomputing/wasm3/enforcer/securebox.h"

#include <cstdint>
#include <optional>

#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/enforcer/crypto_internal.h"
#include "third_party/sealedcomputing/wasm3/logging.h"

namespace sealed {
namespace wasm {
namespace enforcer {
namespace securebox {
namespace {

const uint8_t kPrivkeyData[P256_SCALAR_NBYTES] = {
    0x46, 0x29, 0x4d, 0xa4, 0x29, 0x57, 0x4e, 0xea, 0xf0, 0xa8, 0x85,
    0x44, 0x59, 0x40, 0xe5, 0x78, 0x58, 0xcd, 0xd0, 0xaf, 0x6,  0xfa,
    0xee, 0xa1, 0xe1, 0xe4, 0x27, 0x15, 0x34, 0x75, 0x1c, 0xbe};

const uint8_t kPlaintextData[] = {
    0xe0, 0x12, 0x33, 0x8a, 0xf6, 0xc0, 0x96, 0x58, 0x1c, 0x8,  0x59, 0x86,
    0x8a, 0x30, 0x71, 0x4b, 0x57, 0x1e, 0xfa, 0x2,  0xf4, 0x18, 0xc9, 0xd,
    0x6f, 0x2c, 0xa3, 0x90, 0x75, 0x3d, 0x71, 0x62, 0x31, 0x32, 0x33, 0x34,
    0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36};

const uint8_t kEncryptedData[] = {
    0x2,  0x0,  0x4,  0xd,  0xd3, 0xbe, 0x71, 0x9c, 0xcd, 0x4,  0x65, 0x95,
    0x74, 0xba, 0xb0, 0x42, 0x6d, 0xce, 0x54, 0x8d, 0xd4, 0x71, 0xc7, 0x9b,
    0x10, 0x1e, 0x31, 0xe8, 0x3a, 0x9,  0x79, 0xf2, 0xe6, 0xd6, 0x3d, 0xe8,
    0x1a, 0x51, 0xd2, 0x11, 0xfa, 0xd2, 0xd2, 0xc5, 0xb8, 0x15, 0xd9, 0xe0,
    0x88, 0xb9, 0x82, 0x48, 0xb2, 0x7b, 0xda, 0x22, 0x6f, 0xf8, 0xc,  0x42,
    0x69, 0x97, 0x1b, 0xeb, 0x12, 0x8f, 0x8b, 0x9,  0x8d, 0xd4, 0xbd, 0x2c,
    0xf4, 0xb4, 0x86, 0x29, 0x4b, 0xbf, 0xa9, 0xa1, 0xb2, 0x7d, 0xdf, 0x77,
    0xe6, 0x61, 0xe,  0x4b, 0xfe, 0x7b, 0x8,  0xca, 0x2a, 0xc8, 0x1f, 0x42,
    0x44, 0xbf, 0x8,  0x18, 0xc4, 0x5f, 0x95, 0x21, 0x74, 0x78, 0x32, 0xfb,
    0x26, 0x62, 0x41, 0x3f, 0xdf, 0x75, 0x39, 0xcc, 0x82, 0xb,  0xee, 0x46,
    0xe,  0xcb, 0x1f, 0x64, 0x46, 0xea, 0xd6, 0x4f, 0x70, 0xf5, 0xc1, 0x16,
    0xa1, 0x88, 0x6,  0xb7, 0x9f, 0xbd, 0x8,  0x7,  0x16, 0xb0, 0x47};

const uint8_t kInfo[] = {
    0x56, 0x31, 0x20, 0x4b, 0x46, 0x5f, 0x63, 0x6c, 0x61, 0x69, 0x6d, 0x4,
    0x1e, 0x5a, 0xa9, 0x8a, 0x17, 0x8f, 0x64, 0x87, 0x57, 0x5a, 0x59, 0xae,
    0x84, 0x73, 0x8d, 0xf3, 0x92, 0xe9, 0x54, 0xf5, 0x6c, 0xdc, 0x56, 0x6,
    0x6b, 0x53, 0x4,  0xd3, 0x2b, 0xbc, 0x13, 0xc9, 0x4f, 0x1c, 0xb,  0x50,
    0x86, 0xa7, 0x2,  0x33, 0x7,  0xd2, 0x86, 0x87, 0x89, 0xc8, 0x9,  0x10,
    0xf2, 0x24, 0x93, 0xfa, 0xd5, 0x3e, 0x5b, 0xde, 0x29, 0xa1, 0xd8, 0x8a,
    0x9c, 0x71, 0x46, 0x60, 0x61, 0x62, 0x63, 0x64, 0x0,  0x0,  0x0,  0x0,
    0xa,  0x0,  0x0,  0x0,  0x1,  0x69, 0x6e, 0x73, 0x74, 0x5f, 0x69, 0x64,
    0x2e, 0x64, 0x65, 0x76, 0x5f, 0x69, 0x64, 0x2e, 0x2e, 0x6e, 0x6f, 0x74,
    0x20, 0x61, 0x20, 0x72, 0x65, 0x61, 0x6c, 0x20, 0x76, 0x61, 0x75, 0x6c,
    0x74, 0x20, 0x63, 0x68, 0x61, 0x6c, 0x6c, 0x65, 0x6e, 0x67, 0x65};

const uint8_t kSymmetricSecretData[] = "1234567890123456";

const uint8_t kSymmetricInfoData[] = {
    0x56, 0x31, 0x20, 0x72, 0x65, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70,
    0x74, 0x65, 0x64, 0x5f, 0x72, 0x65, 0x63, 0x6f, 0x76, 0x65, 0x72,
    0x79, 0x5f, 0x6b, 0x65, 0x79, 0x4,  0xf3, 0x21, 0x19, 0x4f, 0x5,
    0x69, 0xaa, 0xa3, 0xa5, 0x76, 0xe1, 0x8d, 0xfc, 0x7,  0x9e, 0x88,
    0x7f, 0x4e, 0x2d, 0x14, 0xd0, 0x8d, 0x17, 0xde, 0x8d, 0x5f, 0x1a,
    0x65, 0xcc, 0x28, 0xfc, 0x27, 0xa6, 0x69, 0x9c, 0x91, 0xbd, 0x94,
    0x70, 0xf,  0x7d, 0x89, 0x7a, 0xd5, 0x46, 0xfb, 0x5c, 0x25, 0xab,
    0xf,  0xc4, 0x56, 0x35, 0xa2, 0xcb, 0x80, 0x5b, 0x60, 0x57, 0x3,
    0x21, 0x60, 0x61, 0xe9, 0x61, 0x62, 0x63, 0x64, 0x0,  0x0,  0x0,
    0x0,  0xa,  0x0,  0x0,  0x0,  0x1,  0x69, 0x6e, 0x73, 0x74, 0x5f,
    0x69, 0x64, 0x2e, 0x64, 0x65, 0x76, 0x5f, 0x69, 0x64, 0x2e, 0x2e};

const uint8_t kSymmetricCiphertextData[] = {
    0x2,  0x0,  0x80, 0x6b, 0x76, 0xce, 0x43, 0x69, 0xc,  0x3d, 0x3f, 0xe1,
    0x23, 0xb3, 0x4e, 0xde, 0xec, 0xbf, 0xf4, 0x47, 0x9c, 0x7f, 0xaa, 0x86,
    0x22, 0xb3, 0x1e, 0x9e, 0xa4, 0xe4, 0x60, 0x77, 0x2b, 0x93, 0xb1, 0x6c,
    0x9d, 0xb1, 0xed, 0xdd, 0x5f, 0x56, 0xea, 0x1a, 0xf3, 0xc,  0x76, 0x4a,
    0xb7, 0x55, 0xc7, 0x44, 0x25, 0x5,  0x4d, 0x5a, 0xaf, 0x18, 0x6d, 0x8d,
    0x32, 0x75, 0x19, 0x98, 0x30, 0x4f, 0x28, 0x37, 0x62, 0x28, 0xef, 0x5c,
    0xd1, 0xf7, 0x5e, 0x1a, 0x33, 0xce, 0x78, 0x4e, 0xbf, 0xc2, 0x9c, 0x57,
    0x96, 0x4f, 0xc5, 0xe3, 0xfc, 0x1b, 0xee};

const uint8_t kSymmetricPlaintextData[] = {
    0x2,  0x0,  0xcb, 0x1f, 0x2a, 0xf7, 0xb9, 0x8f, 0x6d, 0x8b, 0xf5,
    0x78, 0x3,  0x20, 0xff, 0x3c, 0xe0, 0x51, 0x76, 0x76, 0xa3, 0xc5,
    0xaa, 0xd5, 0xcb, 0xa8, 0x12, 0x5b, 0xf5, 0xfa, 0x79, 0xe4, 0xc4,
    0xae, 0x0,  0xe0, 0xce, 0x17, 0x95, 0xec, 0x4,  0xca, 0x65, 0x64,
    0x63, 0xe5, 0x2c, 0x9,  0x78, 0xba, 0x73, 0x55, 0xb,  0xe6, 0x62,
    0x90, 0xe,  0x89, 0x57, 0xd8, 0x3};

// Test a public key encryption vector from an existing SecureboxV2
// implementation to make sure we can decrypt it.
void TestSecureboxPublicKeyVector() {
  SecretByteString server_privkey(kPrivkeyData, sizeof(kPrivkeyData));
  SC_CHECK_EQ(server_privkey.size(), P256_SCALAR_NBYTES);
  ByteString info(kInfo, sizeof(kInfo));
  ByteString ciphertext(kEncryptedData, sizeof(kEncryptedData));
  auto decrypted_plaintext_statusor =
      Decrypt(kVersion2, server_privkey, "", info, ciphertext);
  SC_CHECK_OK(decrypted_plaintext_statusor);
  SecretByteString plaintext(kPlaintextData, sizeof(kPlaintextData));
  SC_CHECK_EQ(*decrypted_plaintext_statusor, plaintext);
}

// Test a symmetric key encryption vector from an existing SecureboxV2
// implementation to make sure we can decrypt it.
void TestSecureboxSymmetricKeyVector() {
  SecretByteString shared_secret(kSymmetricSecretData,
                                 sizeof(kSymmetricSecretData) - 1);
  ByteString info(kSymmetricInfoData, sizeof(kSymmetricInfoData));
  ByteString ciphertext(kSymmetricCiphertextData,
                        sizeof(kSymmetricCiphertextData));
  auto decrypted_plaintext_statusor =
      Decrypt(kVersion2, "", shared_secret, info, ciphertext);
  SC_CHECK_OK(decrypted_plaintext_statusor);
  SecretByteString plaintext(kSymmetricPlaintextData,
                             sizeof(kSymmetricPlaintextData));
  SC_CHECK_EQ(*decrypted_plaintext_statusor, plaintext);
}

// Test a vector from an existing SecureboxV2 implementation to make sure we can
// decrypt it.
void TestInvalidCiphertext() {
  SecretByteString server_privkey(kPrivkeyData, sizeof(kPrivkeyData));
  ByteString info(kInfo, sizeof(kInfo));
  ByteString ciphertext(kEncryptedData, sizeof(kEncryptedData));
  // Flip one bit the ciphertext and verify decrypt fails.
  for (size_t pos = 0; pos < ciphertext.size(); pos++) {
    for (uint8_t bit = 1; bit != 0; bit <<= 1) {
      ciphertext[pos] ^= bit;
      auto decrypted_plaintext_statusor =
          Decrypt(kVersion2, server_privkey, "", info, ciphertext);
      SC_CHECK(!decrypted_plaintext_statusor.ok());
      ciphertext[pos] ^= bit;
    }
  }
  auto decrypted_plaintext_statusor =
      Decrypt(kVersion2, server_privkey, "", info, ciphertext);
  SC_CHECK_OK(decrypted_plaintext_statusor);
}

// Test that we can encrypt and then decrypt a sample message.
void TestEncryptThenDecrypt() {
  // Encrypt a message.
  auto server_privkey_statusor = RandomPrivkey(kVersion2);
  SC_CHECK_OK(server_privkey_statusor);
  SecretByteString server_privkey = *server_privkey_statusor;
  SC_CHECK_EQ(server_privkey.size(), P256_SCALAR_NBYTES);
  auto server_pubkey_statusor = PubkeyFromPrivkey(kVersion2, server_privkey);
  SC_CHECK_OK(server_pubkey_statusor);
  ByteString server_pubkey = *server_pubkey_statusor;
  SecretByteString shared_secret("shared_secret");
  SecretByteString plaintext = "plaintext";
  ByteString info("info");
  auto ciphertext_statusor =
      Encrypt(kVersion2, server_pubkey, shared_secret, info, plaintext);
  SC_CHECK_OK(ciphertext_statusor);
  ByteString ciphertext = *ciphertext_statusor;
  // Decrypt the ciphertext.
  auto decrypted_plaintext_statusor =
      Decrypt(kVersion2, server_privkey, shared_secret, info, ciphertext);
  SC_CHECK_EQ(plaintext, *decrypted_plaintext_statusor);
}

// Test that we can encrypt and then decrypt with just a shared secret.
// shared secret.
void TestSymmetric() {
  // Encrypt a message.
  SecretByteString shared_secret("shared_secret");
  SecretByteString plaintext = "plaintext";
  ByteString info("info");
  auto ciphertext_statusor =
      Encrypt(kVersion2, "", shared_secret, info, plaintext);
  SC_CHECK_OK(ciphertext_statusor);
  ByteString ciphertext = *ciphertext_statusor;
  // Decrypt the ciphertext.
  auto decrypted_plaintext_statusor =
      Decrypt(kVersion2, "", shared_secret, info, ciphertext);
  SC_CHECK_EQ(plaintext, *decrypted_plaintext_statusor);
}

// Test that we can encrypt and then decrypt with a public key only.
void TestPublicOnly() {
  // Encrypt a message.
  auto server_privkey_statusor = RandomPrivkey(kVersion2);
  SC_CHECK_OK(server_privkey_statusor);
  SecretByteString server_privkey = *server_privkey_statusor;
  SC_CHECK_EQ(server_privkey.size(), P256_SCALAR_NBYTES);
  auto server_pubkey_statusor = PubkeyFromPrivkey(kVersion2, server_privkey);
  SC_CHECK_OK(server_pubkey_statusor);
  ByteString server_pubkey = *server_pubkey_statusor;
  SecretByteString plaintext = "plaintext";
  ByteString info("info");
  auto ciphertext_statusor =
      Encrypt(kVersion2, server_pubkey, "", info, plaintext);
  SC_CHECK_OK(ciphertext_statusor);
  ByteString ciphertext = *ciphertext_statusor;
  // Decrypt the ciphertext.
  auto decrypted_plaintext_statusor =
      Decrypt(kVersion2, server_privkey, "", info, ciphertext);
  SC_CHECK_EQ(plaintext, *decrypted_plaintext_statusor);
}

// Test that we can use derived keys using PrivkeyFromSeed.
void TestWithDerivedKey() {
  ByteString seed("seed");
  ByteString seed_info("seed_info");
  auto server_privkey_statusor = PrivkeyFromSeed(kVersion2, seed, seed_info);
  SC_CHECK_OK(server_privkey_statusor);
  SecretByteString server_privkey = *server_privkey_statusor;
  SC_CHECK_EQ(server_privkey.size(), P256_SCALAR_NBYTES);
  auto server_pubkey_statusor = PubkeyFromPrivkey(kVersion2, server_privkey);
  SC_CHECK_OK(server_pubkey_statusor);
  ByteString server_pubkey = *server_pubkey_statusor;
  SecretByteString shared_secret("shared_secret");
  SecretByteString plaintext = "plaintext";
  ByteString info("info");
  auto ciphertext_statusor =
      Encrypt(kVersion2, server_pubkey, shared_secret, info, plaintext);
  SC_CHECK_OK(ciphertext_statusor);
  ByteString ciphertext = *ciphertext_statusor;
  // Decrypt the ciphertext.
  auto decrypted_plaintext_statusor =
      Decrypt(kVersion2, server_privkey, shared_secret, info, ciphertext);
  SC_CHECK_EQ(plaintext, *decrypted_plaintext_statusor);
}

// Test that PrivkeyFromSeed is deterministic and depends on seed and info.
void TestPrivkeyFromSeed() {
  ByteString seed1("seed1");
  ByteString seed2("seed2");
  ByteString seed_info1("seed_info1");
  ByteString seed_info2("seed_info2");
  // Check that we get the same key if seed and info are the same.
  auto privkey_statusor1 = PrivkeyFromSeed(kVersion2, seed1, seed_info1);
  SC_CHECK_OK(privkey_statusor1);
  SecretByteString privkey1 = *privkey_statusor1;
  auto privkey_statusor2 = PrivkeyFromSeed(kVersion2, seed1, seed_info1);
  SC_CHECK_OK(privkey_statusor2);
  SecretByteString privkey2 = *privkey_statusor2;
  SC_CHECK_EQ(privkey1, privkey2);
  // Check that we get different keys when seeds are different.
  privkey_statusor1 = PrivkeyFromSeed(kVersion2, seed1, seed_info1);
  SC_CHECK_OK(privkey_statusor1);
  privkey1 = *privkey_statusor1;
  privkey_statusor2 = PrivkeyFromSeed(kVersion2, seed2, seed_info1);
  SC_CHECK_OK(privkey_statusor2);
  privkey2 = *privkey_statusor2;
  SC_CHECK_NE(privkey1, privkey2);
  // Check that we get different keys when infos are different.
  privkey_statusor1 = PrivkeyFromSeed(kVersion2, seed1, seed_info1);
  SC_CHECK_OK(privkey_statusor1);
  privkey1 = *privkey_statusor1;
  privkey_statusor2 = PrivkeyFromSeed(kVersion2, seed1, seed_info2);
  SC_CHECK_OK(privkey_statusor2);
  privkey2 = *privkey_statusor2;
  SC_CHECK_NE(privkey1, privkey2);
}

void RunTests() {
  TestSecureboxPublicKeyVector();
  TestSecureboxSymmetricKeyVector();
  TestInvalidCiphertext();
  TestEncryptThenDecrypt();
  TestSymmetric();
  TestPublicOnly();
  TestWithDerivedKey();
  TestPrivkeyFromSeed();
}

}  // namespace
}  // namespace securebox
}  // namespace enforcer
}  // namespace wasm
}  // namespace sealed

int main() {
  sealed::wasm::enforcer::securebox::RunTests();
  SC_LOG(INFO) << "PASSED";
  return 0;
}
