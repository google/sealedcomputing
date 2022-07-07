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

// Provide primitives for logging for tests.

#include "third_party/sealedcomputing/wasm3/enforcer/uefi_crypto/test_fakes.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void biPanic(const void* filename, int32_t line, const void* text) {
  printf("Abort in %s line %u: %s\n", (const char*)filename, line,
         (const char*)(text));
  abort();
}

void biSendLogRpc(int32_t level, const void* filename, int32_t line,
                  const void* text) {
  const char* name = (const char*)filename;
  const char* short_name = strrchr(name, '/');
  if (short_name == NULL) {
    short_name = name;
  } else {
    short_name++;  // Skip the leading '/'.
  }
  static const char* level_name[4] = {"INFO", "WARNING", "ERROR", "FATAL"};
  printf("%s: %s line %u: %s\n", level_name[level], short_name, line,
         (const char*)text);
}

void biRandBytes(void* buf, int32_t len) {
  static uint64_t state = 12345;
  uint8_t* p = buf;
  for (int32_t i = 0; i < len; i++) {
    state = state * 0xcafebabedeadbeefllu;
    state ^= state >> 16;
    state += 0xdeadbeef;
    p[i] = state;
  }
}
