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

#include "third_party/sealedcomputing/wasm3/keyset_policies/external_sealer.h"

#include "third_party/sealedcomputing/wasm3/crypto.h"
#include "third_party/sealedcomputing/wasm3/status.h"

namespace sealed {
namespace wasm {
namespace {

using ::sealed::wasm::enforcer::AesGcm;

// Length of the serialized version code.
constexpr size_t kVersionSize = 1;

// Version of the serialized format. Right now there is only version 0.
constexpr uint8_t kVersion[] = {0x00};

// Length of a nonce for the AES GCM algorithm.
constexpr size_t kAesGcmNonceSize = 12;

}  // namespace

StatusOr<std::unique_ptr<ExternalSealer>> ExternalSealer::Create(
    std::unique_ptr<AesGcm> aes_gcm) {
  if (!aes_gcm) {
    return Status(kInvalidArgument, "AesGcm is not set");
  }
  return std::unique_ptr<ExternalSealer>(
      new ExternalSealer(std::move(aes_gcm)));
}

ExternalSealer::ExternalSealer(std::unique_ptr<AesGcm> aes_gcm)
    : aes_gcm_(std::move(aes_gcm)) {}

ByteString ExternalSealer::Encrypt(const ByteString& plaintext,
                                   const ByteString& aad) {
  SecretByteString nonce = RandBytes(kAesGcmNonceSize);
  return ByteString(kVersion) + nonce +
         aes_gcm_->Encrypt(nonce, plaintext, aad);
}

bool ExternalSealer::Decrypt(const ByteString& ciphertext,
                             const ByteString& aad, ByteString* plaintext) {
  if (ciphertext.size() < kVersionSize + kAesGcmNonceSize) {
    return false;
  }

  if (ciphertext[0] != *kVersion) {
    return false;
  }

  ByteString nonce = ciphertext.substr(kVersionSize, kAesGcmNonceSize);
  ByteString aes_gcm_ciphertext =
      ciphertext.substr(kVersionSize + kAesGcmNonceSize);
  StatusOr<SecretByteString> result =
      aes_gcm_->Decrypt(nonce, aes_gcm_ciphertext, aad);
  if (!result.ok()) {
    return false;
  }

  *plaintext = *result;
  return true;
}

}  // namespace wasm
}  // namespace sealed
