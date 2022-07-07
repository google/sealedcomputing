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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_LITE_FIBER_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_LITE_FIBER_H_

#include <cstdlib>
#include <memory>

#include "third_party/fiber/include/fiber/fiber.h"
#include "third_party/sealedcomputing/wasm3/enforcer/fiber.h"

namespace sealed {
namespace wasm {

// A lightweight fibers implementation using //third_party/fiber.
class LiteFiber : public FiberInterface {
 public:
  ~LiteFiber();

  void SwitchTo(FiberInterface* fiber) override;
  void Yield() override;
  bool IsDone() const override;

  // Use once to create top-level fiber. This is used to spawn new fibers.
  static std::unique_ptr<LiteFiber> NewTopLevelFiber();
  std::unique_ptr<FiberInterface> NewFiber(FiberFunc f, void* args);

 private:
  static void FiberFunc(void* args);
  LiteFiber(Fiber* caller, Fiber* self) : caller_(caller), self_(self) {}

  // Non-owning pointer.
  Fiber* caller_;
  // Owning pointer.
  Fiber* self_;
  bool done_ = false;
};

}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_LITE_FIBER_H_
