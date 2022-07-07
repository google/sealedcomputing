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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_UEFI_CRYPTO_SHA256_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_UEFI_CRYPTO_SHA256_H_

#include <unistd.h>

#include "third_party/openssl/boringssl/src/include/openssl/sha.h"
#include "third_party/sealedcomputing/wasm3/base.h"
#include "third_party/sealedcomputing/wasm3/bytestring.h"

namespace sealed {
namespace wasm {
namespace uefi_crypto {

constexpr size_t kSha256DigestLength = SHA256_DIGEST_LENGTH;
constexpr size_t kSha256CBlockLength = SHA256_CBLOCK;

struct Sha256Ctx {
  ~Sha256Ctx() { Cleanse(&ctx, sizeof(ctx)); }

  SHA256_CTX ctx;
};

void Sha256Init(Sha256Ctx* ctx);
void Sha256Update(Sha256Ctx* ctx, const ByteString& data);
// These two call malloc, which may dominate the runtime.
SecretByteString Sha256Final(Sha256Ctx* ctx);
SecretByteString Sha256(const ByteString& data);

// If you want to hash faster, call the following overloads instead of the ones
// which return SecretByteString.  These two functions avoid calling malloc.
void Sha256Final(Sha256Ctx* ctx, SecretByteString* digest);
void Sha256(const ByteString& data, SecretByteString* digest);

}  // namespace uefi_crypto
}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_UEFI_CRYPTO_SHA256_H_
