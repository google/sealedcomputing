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

#include "third_party/sealedcomputing/wasm3/enforcer/lite_fiber.h"

#include "third_party/sealedcomputing/wasm3/enforcer/fiber.h"

namespace sealed {
namespace wasm {
namespace {

// cs/third_party/fiber/README.md recommends a conservative stack size of 32kB.
constexpr size_t kStackSize = 1024 * 32;

// This is called if a fiber is switched to after it is finished.
void guard(Fiber* self, void* null) {
  (void)self;
  (void)null;
  abort();
}

typedef struct {
  void* arg;
  LiteFiber* self;
  FiberInterface::FiberFunc fp;
} FiberFuncArgs;

}  // namespace

void LiteFiber::FiberFunc(void* args) {
  FiberFuncArgs* fiber_runner_args = static_cast<FiberFuncArgs*>(args);
  fiber_runner_args->fp(fiber_runner_args->arg, fiber_runner_args->self);
  fiber_runner_args->self->done_ = true;
  fiber_switch(fiber_runner_args->self->self_,
               fiber_runner_args->self->caller_);
}

LiteFiber::~LiteFiber() {
  if (!fiber_is_toplevel(self_)) fiber_destroy(self_);
  delete self_;
}

void LiteFiber::SwitchTo(FiberInterface* fiber) {
  auto lite_fiber = static_cast<LiteFiber*>(fiber);
  fiber_switch(self_, lite_fiber->self_);
}

void LiteFiber::Yield() { fiber_switch(self_, caller_); }

bool LiteFiber::IsDone() const { return done_; }

std::unique_ptr<LiteFiber> LiteFiber::NewTopLevelFiber() {
  Fiber* main_fiber = new Fiber{};
  fiber_init_toplevel(main_fiber);
  return std::unique_ptr<LiteFiber>(new LiteFiber(nullptr, main_fiber));
}

std::unique_ptr<FiberInterface> LiteFiber::NewFiber(FiberInterface::FiberFunc f,
                                                    void* args) {
  Fiber* fiber = new Fiber{};
  // Additionally add an unmapped page guard to detect overflows.
  (void)fiber_alloc(fiber, kStackSize, guard, NULL, FIBER_FLAG_GUARD_LO);
  auto callee = new LiteFiber(self_, fiber);
  FiberFuncArgs fiber_func_args{
      .arg = args,
      .self = callee,
      .fp = f,
  };
  fiber_push_return(fiber, &FiberFunc, &fiber_func_args,
                    sizeof fiber_func_args);
  return std::unique_ptr<FiberInterface>(callee);
}

}  // namespace wasm
}  // namespace sealed
