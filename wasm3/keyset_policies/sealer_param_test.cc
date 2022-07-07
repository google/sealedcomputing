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

#include "third_party/sealedcomputing/wasm3/keyset_policies/sealer_param_test.h"

namespace sealed::wasm {
namespace {

constexpr char kSerializedTaskConfig[] = "a fake task config";
constexpr char kAad[] = "aad";
constexpr char kPlaintext[] = "plaintext";

TEST_P(SealerParamTest, EncryptAndDecrypt) {
  auto sealer = (*GetParam())();
  ByteString ciphertext = sealer->Encrypt(kPlaintext, kAad);
  ByteString plaintext;
  ASSERT_TRUE(sealer->Decrypt(ciphertext, kAad, &plaintext));
  EXPECT_EQ(plaintext, kPlaintext);
}

TEST_P(SealerParamTest, BadAad) {
  auto sealer = (*GetParam())();
  ByteString ciphertext = sealer->Encrypt(kPlaintext, kAad);
  ByteString plaintext;
  ASSERT_FALSE(sealer->Decrypt(ciphertext, "bad aad", &plaintext));
  EXPECT_TRUE(plaintext.empty());
}

TEST_P(SealerParamTest, BadCiphertext) {
  auto sealer = (*GetParam())();
  ByteString ciphertext = sealer->Encrypt(kPlaintext, kAad);
  ByteString plaintext;
  ASSERT_FALSE(sealer->Decrypt("bad ciphertext", kAad, &plaintext));
  EXPECT_TRUE(plaintext.empty());
}

TEST_P(SealerParamTest, SecretsArePersisted) {
  ByteString ciphertext;
  {
    auto sealer = (*GetParam())();
    ciphertext = sealer->Encrypt(kPlaintext, kAad);
  }
  auto sealer = (*GetParam())();
  ByteString plaintext;
  ASSERT_TRUE(sealer->Decrypt(ciphertext, kAad, &plaintext));
  EXPECT_EQ(plaintext, kPlaintext);
}

}  // namespace
}  // namespace sealed::wasm
