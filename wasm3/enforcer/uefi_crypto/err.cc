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

#include "third_party/sealedcomputing/wasm3/enforcer/uefi_crypto/openssl/err.h"

#include <stdio.h>

#include "third_party/sealedcomputing/wasm3/logging.h"

extern "C" {

void ERR_put_error(int library, int unused, int reason, const char *file,
                   unsigned line) {
  char l[20];
  sprintf(l, "%u", line);  // NOLINT
  SC_LOG(DEBUG) << "BoringSSL error in file " << file << ", line " << l << "\n";
}

void ERR_clear_error() {}

uint32_t ERR_peek_last_error(void) { return 0; }

}  // exterm "C"
