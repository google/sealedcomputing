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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_KEYSET_POLICIES_SEALER_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_KEYSET_POLICIES_SEALER_H_

#include "third_party/sealedcomputing/wasm3/bytestring.h"

namespace sealed {
namespace wasm {

// This class provides an API to seal and unseal data.
class Sealer {
 public:
  virtual ~Sealer() = default;
  // Encrypts `plaintext` and binds it to `aad`.
  virtual ByteString Encrypt(const ByteString& plaintext,
                             const ByteString& aad) = 0;

  // Verifies `aad` was bound to `ciphertext` and decrypts `ciphertext`. The
  // result is written to `plaintext`.
  virtual bool Decrypt(const ByteString& ciphertext, const ByteString& aad,
                       ByteString* plaintext) = 0;
};

}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_KEYSET_POLICIES_SEALER_H_
