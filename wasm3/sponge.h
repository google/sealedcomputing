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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_SPONGE_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_SPONGE_H_

#include <cstddef>
#include <cstdint>
#include <memory>

#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/crypto.h"
#include "third_party/sealedcomputing/wasm3/logging.h"

namespace sealed {
namespace wasm {

struct SpongeState {
  SpongeState() : data(kSha256DigestLength) {}
  SecretByteString XorDataAndCounter(uint64_t counter);

  SecretByteString data;
  uint64_t counter = 0;
};

// In short, this is a cryptographic sponge, almost.  It does things a bit
// differently to protect users from themselves, and it uses the Sha256 class.
class Sponge {
 public:
  Sponge() : hash_ctx_(nullptr) {}
  // This is a non-streaming API.  If you call Absorb("abc"), and then
  // Absorb("def"), you get a different state than if you call Absorb("abcdef").
  // If you need a streaming API, use AbsorbInit/AbsorbUpdate/AbsorbeFinal.
  // This behavior is chosen to help users write secure code.  A very common
  // mistake is to call Absorb twice in a row on variable length inputs, causing
  // an ambiguity when interpreting the input data, typically leading to
  // collisions.
  void Absorb(const SecretByteString& data);
  // This is a streaming API.
  SecretByteString Squeeze(size_t length);
  // Return a 32-byte block that would be squeezed  afer
  // |block_num| calls to Squeeze(32) since the last Absorb.
  SecretByteString BlockAt(size_t block_num);

  // These are streaming APIs for applications that need to absorb an unknown
  // amount of data.
  void AbsorbInit();
  void AbsorbUpdate(const SecretByteString& data);
  void AbsorbFinal();

 private:
  SpongeState state_;
  SecretByteString remaining_bits_;
  // For streaming Absorb(Init/Update/Final) APIs.
  std::unique_ptr<Sha256> hash_ctx_;
};

}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_SPONGE_H_
