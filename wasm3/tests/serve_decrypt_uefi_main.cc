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

#include "third_party/sealedcomputing/wasm3/efi_utils.h"
#include "third_party/sealedcomputing/wasm3/enforcer/wasm.h"
#include "third_party/sealedcomputing/wasm3/status.h"

int main() {
  extern const char serve_decrypt_sealing_policy_wasm_data_start[];
  extern const char serve_decrypt_sealing_policy_wasm_data_end[];
  size_t wasm_data_size = serve_decrypt_sealing_policy_wasm_data_end -
                          serve_decrypt_sealing_policy_wasm_data_start;

  sealed::wasm::Status status = sealed::wasm::InitWasm(
      serve_decrypt_sealing_policy_wasm_data_start, wasm_data_size);
  if (!status) {
    fprintf(stderr, "Unable to start bytecode interpreter: %s\n",
            status.message().c_str());
    return 1;
  }
  disable_watchdog_timer();
  status = sealed::wasm::RunWasmMain();
  if (!status) {
    fprintf(stderr, "Unable to run bytecode interpreter: %s\n",
            status.message().c_str());
    return 1;
  }
  return 0;
}
