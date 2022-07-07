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

#include "third_party/sealedcomputing/wasm3/enforcer/uefi_crypto/hmac_sha256.h"

#include <stdint.h>
#include <string.h>

#include "third_party/openssl/boringssl/src/include/openssl/mem.h"
#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/enforcer/uefi_crypto/init_crypto.h"
#include "third_party/sealedcomputing/wasm3/enforcer/uefi_crypto/sha256.h"

namespace sealed {
namespace wasm {
namespace uefi_crypto {

constexpr uint8_t kInnerPad = 0x36;
constexpr uint8_t kOuterPad = 0x5c;

void HmacSha256Init(HmacSha256Ctx* ctx, const SecretByteString& key) {
  if (!global_initialized) {
    InitializeCryptoLib();
  }
  const uint8_t* key_ptr = key.data();
  size_t key_len = key.size();
  SecretByteString key_digest(kSha256DigestLength);
  if (key_len > kSha256CBlockLength) {
    // Note: This causes trivial collisions.  HMAC is not collision resistant!.
    Sha256(key, &key_digest);
    key_ptr = key_digest.data();
    key_len = kSha256DigestLength;
  }
  Sha256Init(&ctx->sha256_ctx);
  SC_CHECK(ctx->pad.size() == kSha256CBlockLength);
  memset(ctx->pad.data(), kInnerPad, ctx->pad.size());
  for (size_t i = 0; i < key_len; i++) {
    ctx->pad[i] ^= key_ptr[i];
  }
  Sha256Update(&ctx->sha256_ctx, ctx->pad);
  for (size_t i = 0; i < kSha256CBlockLength; i++) {
    ctx->pad[i] ^= kInnerPad ^ kOuterPad;
  }
}

void HmacSha256Update(HmacSha256Ctx* ctx, const ByteString& data) {
  if (!global_initialized) {
    InitializeCryptoLib();
  }
  Sha256Update(&ctx->sha256_ctx, data);
}

SecretByteString HmacSha256Final(HmacSha256Ctx* ctx) {
  if (!global_initialized) {
    InitializeCryptoLib();
  }
  SecretByteString digest(kSha256DigestLength);
  Sha256Final(&ctx->sha256_ctx, &digest);
  Sha256Init(&ctx->sha256_ctx);
  Sha256Update(&ctx->sha256_ctx, ctx->pad);
  Sha256Update(&ctx->sha256_ctx, digest);
  Sha256Final(&ctx->sha256_ctx, &digest);
  return digest;
}

SecretByteString HmacSha256(const SecretByteString& key,
                            const ByteString& data) {
  if (!global_initialized) {
    InitializeCryptoLib();
  }
  HmacSha256Ctx ctx;
  HmacSha256Init(&ctx, key);
  HmacSha256Update(&ctx, data);
  return HmacSha256Final(&ctx);
}

}  // namespace uefi_crypto
}  // namespace wasm
}  // namespace sealed
