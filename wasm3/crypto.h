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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_BUILTIN_CRYPTO_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_BUILTIN_CRYPTO_H_

#include <string>

#include "third_party/sealedcomputing/wasm3/builtin/wasm_types.h"
#include "third_party/sealedcomputing/wasm3/bytestring.h"

namespace sealed {
namespace wasm {

constexpr size_t kSha256DigestLength = 32;

class Sha256 {
 public:
  Sha256();
  explicit Sha256(const ByteString& data);
  ~Sha256();

  void Update(const ByteString& data);
  ByteString Final();
  void Clear();

  static ByteString Digest(const ByteString& data);

 private:
  biOpaqueSha256 opaque_sha_;
  bool finalized_ = false;
  ByteString digest_;
};

class HmacSha256 {
 public:
  HmacSha256(const SecretByteString& key);
  ~HmacSha256();
  void Update(const ByteString& data);
  ByteString Final();
  void Clear();

  static ByteString Digest(const SecretByteString& key, const ByteString& data);

 private:
  SecretByteString key_;
  biOpaqueHmac opaque_hmac_;
  bool finalized_ = false;
  ByteString digest_;
};

// Return random bytes suitable for use as secret keys.
SecretByteString RandBytes(size_t len);

}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_BUILTIN_CRYPTO_H_
