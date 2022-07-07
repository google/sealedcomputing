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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_KEYSET_POLICIES_PUBLIC_KEY_SIGN_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_KEYSET_POLICIES_PUBLIC_KEY_SIGN_H_

#include <string>

#include "third_party/sealedcomputing/wasm3/status.h"

namespace sealed {
namespace wasm {

// Interface for public key signing.
// See third_party/tink/cc/public_key_sign.h
// Note: this interface represents a single signing purpose for the signing key.
// Secure implementations must include an identifier for this signing purpose in
// the data that is signed.
class PublicKeySign {
 public:
  virtual Status Sign(const std::string& data,
                      std::string* signature) const = 0;

  virtual ~PublicKeySign() {}
};

}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_KEYSET_POLICIES_PUBLIC_KEY_SIGN_H_
