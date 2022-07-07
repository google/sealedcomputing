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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_KEYSET_POLICIES_EXTERNAL_SEALER_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_KEYSET_POLICIES_EXTERNAL_SEALER_H_

#include <memory>

#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/enforcer/crypto_internal.h"
#include "third_party/sealedcomputing/wasm3/keyset_policies/sealer.h"
#include "third_party/sealedcomputing/wasm3/statusor.h"

namespace sealed {
namespace wasm {

// A Sealer that is provided its key during construction.
//
// This class mimics hardware-bound secrets through an externally provided key.
class ExternalSealer : public Sealer {
 public:
  static StatusOr<std::unique_ptr<ExternalSealer>> Create(
      std::unique_ptr<enforcer::AesGcm> aes_gcm);

  ByteString Encrypt(const ByteString& plaintext,
                     const ByteString& aad) override;
  bool Decrypt(const ByteString& ciphertext, const ByteString& aad,
               ByteString* plaintext) override;

 private:
  ExternalSealer(std::unique_ptr<enforcer::AesGcm> aes_gcm);

  std::unique_ptr<enforcer::AesGcm> aes_gcm_;
};

}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_KEYSET_POLICIES_EXTERNAL_SEALER_H_
