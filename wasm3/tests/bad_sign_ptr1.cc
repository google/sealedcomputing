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

#include <string>

#include "third_party/sealedcomputing/wasm3/base.h"

WASM_EXPORT int start() {
  char* bad_ptr = (char*)0xffffffff;
  char report_buf[sealed::wasm::kSerializedReportLength];
  char sig_buf[sealed::wasm::kSignatureLength];

  biSign(bad_ptr, 1, report_buf, sig_buf);
  return 0;
}
