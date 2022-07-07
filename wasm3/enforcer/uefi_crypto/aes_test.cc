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

#include "third_party/sealedcomputing/wasm3/base.h"
#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/enforcer/uefi_crypto/test_fakes.h"
#include "third_party/sealedcomputing/wasm3/logging.h"
#include "third_party/sealedcomputing/wasm3/statusor.h"

namespace sealed {
namespace wasm {
namespace uefi_crypto {
namespace {

// Test that AES-GCM-128 can encrypt then decrypt.
void AesGcm128Test() {
  SecretByteString key("0123456789abcdef");
  ByteString nonce("0123456789ab");
  SecretByteString plaintext = "This is a test";
  ByteString associated_data = "Top Secret";
  StatusOr<ByteString> enc_res =
      AesGcmEncrypt(key, nonce, plaintext, associated_data);
  SC_CHECK_OK(enc_res);
  ByteString ciphertext = *enc_res;
  SC_CHECK(ciphertext.size() == plaintext.size() + kAesGcmTagLength);
  StatusOr<SecretByteString> dec_res =
      AesGcmDecrypt(key, nonce, ciphertext, associated_data);
  SC_CHECK_OK(dec_res);
  SC_LOG(INFO) << "Decrypted text: " << *dec_res;
  SC_CHECK(*dec_res == plaintext);
  SC_LOG(INFO) << ciphertext.hex();
  SC_LOG(INFO) << "Passed AesGcm128Test";
}

// Test that AES-GCM-256 can encrypt then decrypt.
void AesGcm256Test() {
  SecretByteString key("0123456789abcdef0123456789abcdef");
  ByteString nonce("0123456789ab");
  SecretByteString plaintext = "This is a test";
  ByteString associated_data = "Top Secret";
  StatusOr<ByteString> enc_res =
      AesGcmEncrypt(key, nonce, plaintext, associated_data);
  SC_CHECK_OK(enc_res);
  ByteString ciphertext = *enc_res;
  SC_CHECK(ciphertext.size() == plaintext.size() + kAesGcmTagLength);
  StatusOr<SecretByteString> dec_res =
      AesGcmDecrypt(key, nonce, ciphertext, associated_data);
  SC_CHECK_OK(dec_res);
  SC_LOG(INFO) << "Decrypted text: " << *dec_res;
  SC_CHECK(*dec_res == plaintext);
  SC_LOG(INFO) << ciphertext.hex();
  SC_LOG(INFO) << "Passed AesGcm256Test";
}

// Test that we get the expected cipher texts.
void AesGcm256VectorTest() {
  ByteString key(32, '\0');
  ByteString ciphertext = *AesGcmEncrypt(key, "0123456789ab", "Test", "");
  ByteString expected =
      "\x42\xe3\x0e\x24\x65\x5f\xc0\x30\x74\xa5\x82\x3f\x1f\x3a\xd4\x07\x6c\xc8"
      "\xbf\x8a";
  SC_CHECK_EQ(ciphertext, expected);
}

// Verify we can encrypt an empty string.
void AesGcmEmptyTest() {
  ByteString key(32, '\0');
  auto ciphertext = AesGcmEncrypt(key, "0123456789ab", "", "");
  SC_CHECK_EQ(ciphertext.status().code(), kInvalidArgument);
}

// Test that we can encrypt/decrypt an AES block.
void AesBlockTest() {
  SecretByteString key128("0123456789abcdef");
  SecretByteString in("0123456789abcdef");
  ByteString out(kAesBlockSize);
  AesEncryptBlock(key128, in, &out);
  SecretByteString recovered(kAesBlockSize);
  AesDecryptBlock(key128, out, &recovered);
  SC_CHECK_EQ(in, recovered);
  SecretByteString key256("0123456789abcdef0123456789abcdef");
  AesEncryptBlock(key256, in, &out);
  AesDecryptBlock(key256, out, &recovered);
  SC_CHECK_EQ(in, recovered);
  SC_LOG(INFO) << "Passed AesBlockTest";
}

}  // namespace
}  // namespace uefi_crypto
}  // namespace wasm
}  // namespace sealed

int main() {
  sealed::wasm::uefi_crypto::AesGcm128Test();
  sealed::wasm::uefi_crypto::AesGcm256Test();
  sealed::wasm::uefi_crypto::AesGcm256VectorTest();
  sealed::wasm::uefi_crypto::AesGcmEmptyTest();
  sealed::wasm::uefi_crypto::AesBlockTest();
  SC_LOG(INFO) << "PASSED";
  return 0;
}
