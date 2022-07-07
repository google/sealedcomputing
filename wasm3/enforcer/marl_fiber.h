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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_MARL_FIBER_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_MARL_FIBER_H_

#include "third_party/marl/include/marl/event.h"
#include "third_party/marl/include/marl/scheduler.h"
#include "third_party/sealedcomputing/wasm3/enforcer/fiber.h"

namespace sealed {
namespace wasm {

class MarlFiber : public FiberInterface {
 public:
  ~MarlFiber() {
    if (scheduler_ != nullptr) {
      scheduler_->unbind();
    }
  }
  void SwitchTo(FiberInterface* fiber) override;
  void Yield() override;
  bool IsDone() const override { return done_; };

  // Use once to create top-level fiber (that owns scheduling).
  // This must outlive all other fibers.
  static std::unique_ptr<FiberInterface> NewTopLevelFiber();

  static std::unique_ptr<FiberInterface> NewFiber(FiberFunc f, void* args);

 private:
  MarlFiber(marl::Event suspend_self, marl::Event suspend_caller)
      : suspend_self_(new marl::Event(suspend_self)),
        suspend_caller_(new marl::Event(suspend_caller)),
        scheduler_(nullptr) {}
  explicit MarlFiber(std::unique_ptr<marl::Scheduler> scheduler)
      : suspend_self_(new marl::Event()),
        suspend_caller_(new marl::Event()),
        scheduler_(std::move(scheduler)) {}

  std::unique_ptr<marl::Event> suspend_self_;
  std::unique_ptr<marl::Event> suspend_caller_;
  // Non-null only and only for top level fiber.
  std::unique_ptr<marl::Scheduler> scheduler_;
  bool done_ = false;
};

}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_MARL_FIBER_H_
