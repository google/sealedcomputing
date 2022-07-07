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

// This is a wrapper around boringssl/src/crypto/fipsmodule/bn/div.c, so that we
// can force BN_CAN_DIVIDE_ULLONG to false.  The issue is our compiler is from
// 2018, back when support was lacking for divide/modulus of 128-bit numbers.
// The file crypto/internal.h sets this flag with no flag we can set to turn it
// off.  So, instead, #include "crypto/internal.h", then #undef
// BN_CAN_DIVIDE_ULLONG, and then #include div.c.

#include "third_party/openssl/boringssl/src/crypto/internal.h"

#undef BORINGSSL_CAN_DIVIDE_UINT128

#include "third_party/openssl/boringssl/src/crypto/fipsmodule/bn/div.c"
