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

#include "third_party/sealedcomputing/wasm3/crypto.h"

#include "third_party/sealedcomputing/wasm3/builtin/crypto_wasm.h"

namespace sealed {
namespace wasm {

Sha256::Sha256() : opaque_sha_(biSha256init()), digest_(kSha256DigestLength) {}

Sha256::Sha256(const ByteString& data)
    : opaque_sha_(biSha256init()), digest_(kSha256DigestLength) {
  Update(data);
}

Sha256::~Sha256() { Final(); }

void Sha256::Update(const ByteString& data) {
  if (finalized_) {
    Clear();
  }
  biSha256update(opaque_sha_, data.data(), data.size());
}

ByteString Sha256::Final() {
  if (!finalized_) {
    biSha256final(opaque_sha_, digest_.data());
    finalized_ = true;
  }
  return digest_;
}

void Sha256::Clear() {
  if (!finalized_) {
    biSha256final(opaque_sha_, digest_.data());
  }
  finalized_ = false;
  opaque_sha_ = biSha256init();
}

ByteString Sha256::Digest(const ByteString& data) {
  ByteString digest(kSha256DigestLength);
  biSha256(data.data(), data.size(), digest.data());
  return digest;
}

HmacSha256::HmacSha256(const SecretByteString& key)
    : key_(key),
      opaque_hmac_(biHmacSha256init(key_.data(), key_.size())),
      digest_(kSha256DigestLength) {}

HmacSha256::~HmacSha256() { Final(); }

void HmacSha256::Update(const ByteString& data) {
  biHmacSha256update(opaque_hmac_, data.data(), data.size());
}

ByteString HmacSha256::Final() {
  if (!finalized_) {
    biHmacSha256final(opaque_hmac_, digest_.data());
    finalized_ = true;
  }
  return digest_;
}

void HmacSha256::Clear() { finalized_ = false; }

ByteString HmacSha256::Digest(const SecretByteString& key,
                              const ByteString& data) {
  ByteString digest(kSha256DigestLength);
  biHmacSha256(key.data(), key.size(), data.data(), data.size(), digest.data());
  return digest;
}

SecretByteString RandBytes(size_t len) {
  SecretByteString buf(len);
  biRandBytes(buf.data(), len);
  return buf;
}

}  // namespace wasm
}  // namespace sealed
