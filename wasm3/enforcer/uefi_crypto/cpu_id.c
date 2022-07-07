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

// This is OpenSSL/BoringSSL's cached CPU info bits.  It must be included
// when compiling binaries that do not depend on openssl:crypto.

#include "third_party/sealedcomputing/wasm3/enforcer/uefi_crypto/cpu_id.h"

uint32_t OPENSSL_ia32cap_P[4] = {0};

// Various symbols needed to cut OPENSSL_EVP dependencies when porting
// uefi_crypto to native-linked nanolibc.
void* EVP_des_cbc;
void* EVP_des_ecb;
void* EVP_des_ede_cbc;
void* EVP_des_ede;
void* EVP_des_ede3_cbc;
void* EVP_rc2_cbc;
void* EVP_rc4;

