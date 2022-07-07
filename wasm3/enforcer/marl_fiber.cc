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

#include "third_party/sealedcomputing/wasm3/enforcer/marl_fiber.h"

#include <memory>

#include "third_party/marl/include/marl/scheduler.h"
#include "third_party/sealedcomputing/wasm3/enforcer/fiber.h"

namespace sealed::wasm {

void MarlFiber::SwitchTo(FiberInterface* fiber) {
  auto marl_fiber = static_cast<MarlFiber*>(fiber);
  marl_fiber->suspend_self_->signal();
  marl_fiber->suspend_caller_->wait();
}

std::unique_ptr<FiberInterface> MarlFiber::NewFiber(FiberFunc f, void* args) {
  marl::Event suspend_self, suspend_caller = marl::Event();
  auto new_fiber = new MarlFiber(suspend_self, suspend_caller);
  bool* done = &new_fiber->done_;
  marl::schedule([=] {
    suspend_self.wait();
    f(args, new_fiber);
    *done = true;
    suspend_caller.signal();
  });
  return std::unique_ptr<FiberInterface>(new_fiber);
}

void MarlFiber::Yield() {
  suspend_caller_->signal();
  suspend_self_->wait();
}

std::unique_ptr<FiberInterface> MarlFiber::NewTopLevelFiber() {
  marl::Scheduler::Config cfg;
  cfg.setWorkerThreadCount(0);

  auto scheduler = std::unique_ptr<marl::Scheduler>(new marl::Scheduler(cfg));
  scheduler->bind();
  return std::unique_ptr<FiberInterface>(new MarlFiber(std::move(scheduler)));
}

}  // namespace sealed::wasm
