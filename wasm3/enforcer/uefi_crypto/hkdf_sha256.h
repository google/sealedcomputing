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

// The BoringSSL/OpenSSL version of HKDF uses the EVP version of hashing, which
// causes every hashing algorithm available through the EVP interface to get
// sucked in.  HKDF is simple enough to re-implement here

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_UEFI_CRYPTO_HKDF_SHA256_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_UEFI_CRYPTO_HKDF_SHA256_H_

#include <unistd.h>

#include "third_party/sealedcomputing/wasm3/bytestring.h"

namespace sealed {
namespace wasm {
namespace uefi_crypto {

SecretByteString HkdfSha256(size_t out_len, const ByteString& secret,
                            const ByteString& salt, const ByteString& info);

}  // namespace uefi_crypto
}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_UEFI_CRYPTO_HKDF_SHA256_H_
