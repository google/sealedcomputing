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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_UEFI_CRYPTO_OPENSSL_BIO_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_UEFI_CRYPTO_OPENSSL_BIO_H_

#include <stdint.h>
#include <stdio.h>

enum {
  BIO_NOCLOSE,
};

struct bio_st {};

typedef struct bio_st BIO;

int BIO_write(BIO *bio, const void *data, int len);
int BIO_read(BIO *bio, void *data, int len);
BIO *BIO_new_fp(FILE *stream, int close_flag);
void BIO_free(BIO *bio);
void BIO_free_all(BIO *bio);

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_UEFI_CRYPTO_OPENSSL_BIO_H_
