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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_FIBER_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_FIBER_H_

namespace sealed {
namespace wasm {

// Implementations should contain factory methods for Fiber.
class FiberInterface {
 public:
  using FiberFunc = void (*)(void* arg, FiberInterface* self);
  virtual ~FiberInterface() = default;
  // Suspends execution on |this| and switches to given fiber.
  // |this| is referred to as the given fiber's "caller".
  virtual void SwitchTo(FiberInterface* fiber) = 0;
  // Suspends execution on |this| and switches to caller fiber.
  virtual void Yield() = 0;
  virtual bool IsDone() const = 0;
};

}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_FIBER_H_
