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

// This test shows that we can crash the wasm3 interpreter very easily with
// unchecked pointers.  TODO: add pointer range checking and get this test to
// fail as it should.

#include <string>

#include "third_party/sealedcomputing/wasm3/base.h"
#include "third_party/sealedcomputing/wasm3/logging.h"

WASM_EXPORT int start() {
  char* bad_ptr = (char*)0xffffffff;
  biPanic("No file", 0, bad_ptr);
  return 0;
}
