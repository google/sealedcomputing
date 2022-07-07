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

// The BoringSSL/OpenSSL version of HMAC uses the EVP version of hashing, which
// causes every hashing algorithm available through the EVP interface to get
// sucked in.  HMAC is simple enough to re-implement here

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_UEFI_CRYPTO_HMAC_SHA256_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_UEFI_CRYPTO_HMAC_SHA256_H_

#include <stdint.h>

#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/enforcer/uefi_crypto/sha256.h"

namespace sealed {
namespace wasm {
namespace uefi_crypto {

struct HmacSha256Ctx {
  SecretByteString pad{kSha256CBlockLength};
  Sha256Ctx sha256_ctx;
};

void HmacSha256Init(HmacSha256Ctx* ctx, const SecretByteString& key);
void HmacSha256Update(HmacSha256Ctx* ctx, const ByteString& data);
SecretByteString HmacSha256Final(HmacSha256Ctx* ctx);
SecretByteString HmacSha256(const SecretByteString& key,
                            const ByteString& data);

}  // namespace uefi_crypto
}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_UEFI_CRYPTO_HMAC_SHA256_H_
