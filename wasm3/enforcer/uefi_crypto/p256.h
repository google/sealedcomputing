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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_UEFI_CRYPTO_P256_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_UEFI_CRYPTO_P256_H_

#include <unistd.h>

#include "third_party/openssl/boringssl/src/include/openssl/ec_key.h"
#include "third_party/sealedcomputing/wasm3/bytestring.h"

namespace sealed {
namespace wasm {
namespace uefi_crypto {

constexpr size_t kP256PrivKeyBytes = 32;

EC_KEY* DeriveP256KeyFromSecret(const SecretByteString& secret,
                                const ByteString& purpose);

}  // namespace uefi_crypto
}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_UEFI_CRYPTO_P256_H_
