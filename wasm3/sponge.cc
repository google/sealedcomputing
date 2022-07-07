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

#include "third_party/sealedcomputing/wasm3/sponge.h"

#include <cstddef>
#include <cstdint>

#include "third_party/sealedcomputing/wasm3/logging.h"

namespace sealed {
namespace wasm {

SecretByteString SpongeState::XorDataAndCounter(uint64_t counter) {
  SecretByteString result = data;
  uint64_t val = counter;
  for (uint32_t i = 0; i < sizeof(uint64_t); i++) {
    result[i] ^= static_cast<uint8_t>(val);
    val >>= 8;
  }
  return result;
}

void Sponge::Absorb(const SecretByteString& data) {
  ByteString prefix = state_.data;
  // Toggle one bit so the feedback is different than the input to the output
  // stage.
  (prefix.data())[prefix.size() >> 1] ^= 1;
  state_.data = Sha256::Digest(prefix + data);
  state_.counter = 0;
}

SecretByteString Sponge::Squeeze(uint64_t length) {
  SecretByteString prefix;
  if (!remaining_bits_.empty()) {
    if (remaining_bits_.size() >= length) {
      SecretByteString result = remaining_bits_.substr(0, length);
      remaining_bits_ =
          remaining_bits_.substr(length, remaining_bits_.size() - length);
      return result;
    }
    length -= remaining_bits_.size();
    prefix = remaining_bits_;
    remaining_bits_.clear();
  }
  uint64_t num_blocks =
      (length + kSha256DigestLength - 1) / kSha256DigestLength;
  SecretByteString result(num_blocks * kSha256DigestLength);
  for (uint64_t i = 0; i < num_blocks; i++) {
    SecretByteString block =
        Sha256::Digest(state_.XorDataAndCounter(state_.counter));
    state_.counter++;
    SC_CHECK(state_.counter != 0);
    memcpy(result.data() + i * kSha256DigestLength, block.data(),
           kSha256DigestLength);
  }
  if (result.size() > length) {
    remaining_bits_ = result.substr(length, result.size() - length);
  }
  return prefix + result.substr(0, length);
}

void Sponge::AbsorbInit() {
  hash_ctx_ = std::make_unique<Sha256>();
  ByteString prefix = state_.data;
  // Toggle bit 128 so the feedback is different than the input to the output
  // stage.
  (prefix.data())[16] ^= 1;
  hash_ctx_->Update(prefix);
}

void Sponge::AbsorbUpdate(const SecretByteString& data) {
  hash_ctx_->Update(data);
}

void Sponge::AbsorbFinal() {
  state_.data = hash_ctx_->Final();
  hash_ctx_.reset();
  state_.counter = 0;
}

SecretByteString Sponge::BlockAt(uint64_t block_num) {
  return Sha256::Digest(state_.XorDataAndCounter(block_num));
}

}  // namespace wasm
}  // namespace sealed
