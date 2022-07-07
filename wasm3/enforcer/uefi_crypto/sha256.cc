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

// SHA256 implementation wrapping BoringSSL.

#include "third_party/sealedcomputing/wasm3/enforcer/uefi_crypto/sha256.h"

#include <cstdint>
#include <cstdio>
#include <cstring>

#include "third_party/openssl/boringssl/src/include/openssl/sha.h"
#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/enforcer/uefi_crypto/init_crypto.h"

namespace sealed {
namespace wasm {
namespace uefi_crypto {

void Sha256Init(Sha256Ctx* ctx) {
  if (!global_initialized) {
    InitializeCryptoLib();
  }
  SHA256_Init(&ctx->ctx);
}

void Sha256Update(Sha256Ctx* ctx, const ByteString& data) {
  if (!global_initialized) {
    InitializeCryptoLib();
  }
  SHA256_Update(&ctx->ctx, data.data(), data.size());
}

void Sha256Final(Sha256Ctx* ctx, SecretByteString* digest) {
  if (!global_initialized) {
    InitializeCryptoLib();
  }
  SHA256_Final(digest->data(), &ctx->ctx);
}

SecretByteString Sha256Final(Sha256Ctx* ctx) {
  if (!global_initialized) {
    InitializeCryptoLib();
  }
  SecretByteString digest(kSha256DigestLength);
  Sha256Final(ctx, &digest);
  return digest;
}

void Sha256(const ByteString& data, SecretByteString* digest) {
  if (!global_initialized) {
    InitializeCryptoLib();
  }
  Sha256Ctx ctx;
  Sha256Init(&ctx);
  Sha256Update(&ctx, data);
  Sha256Final(&ctx, digest);
}
SecretByteString Sha256(const ByteString& data) {
  if (!global_initialized) {
    InitializeCryptoLib();
  }
  SecretByteString digest(kSha256DigestLength);
  Sha256(data, &digest);
  return digest;
}

}  // namespace uefi_crypto
}  // namespace wasm
}  // namespace sealed
