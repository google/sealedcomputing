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

#include <cstdint>

#include "third_party/sealedcomputing/wasm3/enforcer/trng.h"
#include "third_party/sealedcomputing/wasm3/logging.h"

namespace sealed {
namespace wasm {

// Copied from google3/cloud/gvisor/standalone/base/random.cc, which looks like
// a stronger implementation than I see elsewhere in google3.
// Use the Intel RDRAND instruction to generate a 32 bit random number.
//
// NOTE: Each call to RDRAND on AMD's CPUs takes about 1,200 clock cycles.
// At 3GHz, that's about 0.6us, and since it can fail, this could take a few us.
uint32_t rand32() {
  // RDRAND can fail (indicated by the carry flag not being set) and the
  // implementation guide recommends retrying it up to 10 times in a tight
  // loop. "... the odds of ten failures in a row are astronomically small
  // and would in fact be an indication of a larger CPU issue."
  for (int i = 0; i < 10; ++i) {
    // These local variables are initialized to suppress a
    // use-of-uninitialized-value error from MSAN. This is not necessary for the
    // correctness of this logic.
    uint32_t rnd = 0;
    uint8_t carry = 0;
    asm volatile("rdrand %0; setc %1" : "=r"(rnd), "=qm"(carry));
    if (carry) {
      return rnd;
    }
  }
  SC_LOG(FATAL) << "32-bit RDRAND failed";
  return 0;
}

}  // namespace wasm
}  // namespace sealed
