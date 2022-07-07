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

#include "third_party/sealedcomputing/wasm3/keyset_policies/emulated_sealer.h"

#include <memory>
#include <string>

#include "third_party/sealedcomputing/rpc/encode_decode_lite.h"
#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/enforcer/crypto_internal.h"

namespace sealed {
namespace wasm {
namespace {

constexpr uint8_t kEmulationSeed[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                      0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                      0x0c, 0x0d, 0x0e, 0x0f};

constexpr uint8_t kFixedNonce[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                   0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b};

}  // namespace

std::unique_ptr<EmulatedSealer> EmulatedSealer::Create() {
  return std::unique_ptr<EmulatedSealer>(new EmulatedSealer());
}

ByteString EmulatedSealer::Encrypt(const ByteString& plaintext,
                                   const ByteString& aad) {
  return aes_gcm_->Encrypt(kFixedNonce, plaintext, aad);
}

bool EmulatedSealer::Decrypt(const ByteString& ciphertext,
                             const ByteString& aad, ByteString* plaintext) {
  StatusOr<SecretByteString> result =
      aes_gcm_->Decrypt(kFixedNonce, ciphertext, aad);
  if (!result.ok()) {
    return false;
  }
  *plaintext = *result;
  return true;
}

EmulatedSealer::EmulatedSealer()
    : aes_gcm_(std::make_unique<enforcer::AesGcm>(kEmulationSeed)) {}

}  // namespace wasm
}  // namespace sealed
