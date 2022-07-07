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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_TRNG_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_TRNG_H_

#include <cstdint>

namespace sealed {
namespace wasm {

// Return a true random 32-bit value.  The TRNG is highly system-dependent, so
// use this common API to abstract away the hardware.  On x86, it just returns
// the result or the rdrand assembly instruction.
//
// NOTE: Do not use this function to directly generate secret keys!
//
// This function should only be used to help seed a CPRNG,which should also be
// seeded with any hardware-provided secrets such as wrapping keys.  This helps
// protect against back-doored TRNGs such as Dual_EC_DRBG.  See:
// https://en.wikipedia.org/wiki/Dual_EC_DRBG
uint32_t rand32();

}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_TRNG_H_
