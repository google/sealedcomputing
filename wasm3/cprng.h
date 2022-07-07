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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_CPRNG_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_CPRNG_H_

#include "third_party/sealedcomputing/wasm3/sponge.h"

namespace sealed {
namespace wasm {

// This is a NIST Hash-DRBG algorithm, based on our sponge.
class Cprng {
 public:
  // Min seed length in NIST Hash-DRGB.
  static constexpr size_t kMinSeedLength = 32;
  // This can be called multiple times at any point to re-seed the CPRNG.
  // |data| should have enough entropy (unguessability) to meet the security
  // parameter, e.g. 256 true random bits or more.
  void Seed(SecretByteString data) {
    sponge_.Absorb(data);
    // It is important to fully seed the CPRNG all at once.
    SC_CHECK(data.size() >= kMinSeedLength);
    initialized_ = true;
  }
  SecretByteString RandBytes(size_t length) {
    SC_CHECK(initialized_);
    SecretByteString rand_bytes = sponge_.Squeeze(length);
    // Prevent "backtracking" attacks.
    sponge_.Absorb(ByteString(1, '\x02'));
    return rand_bytes;
  }
  bool Initialized() const { return initialized_; }

 private:
  Sponge sponge_;
  bool initialized_ = false;
};

}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_CPRNG_H_
