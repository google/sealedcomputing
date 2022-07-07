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

#include "third_party/sealedcomputing/wasm3/enforcer/uefi_crypto/openssl/bio.h"

#include <unistd.h>

static BIO global_bio;

int BIO_write(BIO* bio, const void* data, int len) {
  return write(STDOUT_FILENO, data, len);
}

int BIO_read(BIO* bio, void* data, int len) {
  return read(STDIN_FILENO, data, len);
}

BIO* BIO_new_fp(FILE* stream, int close_flag) { return &global_bio; }

void BIO_free(BIO* bio) {}

void BIO_free_all(BIO* bio) {}
