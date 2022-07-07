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

// Tests AVX2 implementation of scalar point multiplication of NIST ECC curve
// secp256r1.  These tests can be used as benchmarks for the SecureBox-V2 public
// key encryption/decryption.  This code only uses code that can run inside the
// UEFI enclave, so that it can be compiled both as a native linux test and as a
// test run manually inside the confidential UEFI sandbox.

#include "third_party/sealedcomputing/wasm3/enforcer/uefi_crypto/p256.h"

#include <cstdint>
#include <cstdio>
#include <cstring>

#include "third_party/openssl/boringssl/src/include/openssl/bn.h"
#include "third_party/openssl/boringssl/src/include/openssl/ec.h"
#include "third_party/openssl/boringssl/src/include/openssl/nid.h"
#include "third_party/sealedcomputing/wasm3/base.h"
#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/enforcer/uefi_crypto/test_fakes.h"
#include "third_party/sealedcomputing/wasm3/logging.h"

namespace sealed {
namespace wasm {
namespace uefi_crypto {
namespace {

void BaseMulTest() {
  EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  EC_POINT* res = EC_POINT_new(group);
  const uint8_t d[32] = {0xc4, 0x77, 0xf9, 0xf6, 0x5c, 0x22, 0xcc, 0xe2,
                         0x06, 0x57, 0xfa, 0xa5, 0xb2, 0xd1, 0xd8, 0x12,
                         0x23, 0x36, 0xf8, 0x51, 0xa5, 0x08, 0xa1, 0xed,
                         0x04, 0xe4, 0x79, 0xc3, 0x49, 0x85, 0xbf, 0x96};
  const uint8_t x[32] = {0xb7, 0xe0, 0x8a, 0xfd, 0xfe, 0x94, 0xba, 0xd3,
                         0xf1, 0xdc, 0x8c, 0x73, 0x47, 0x98, 0xba, 0x1c,
                         0x62, 0xb3, 0xa0, 0xad, 0x1e, 0x9e, 0xa2, 0xa3,
                         0x82, 0x01, 0xcd, 0x08, 0x89, 0xbc, 0x7a, 0x19};
  const uint8_t y[32] = {0x36, 0x03, 0xf7, 0x47, 0x95, 0x9d, 0xbf, 0x7a,
                         0x4b, 0xb2, 0x26, 0xe4, 0x19, 0x28, 0x72, 0x90,
                         0x63, 0xad, 0xc7, 0xae, 0x43, 0x52, 0x9e, 0x61,
                         0xb5, 0x63, 0xbb, 0xc6, 0x06, 0xcc, 0x5e, 0x09};
  BIGNUM* bn_d = BN_bin2bn(d, 32, nullptr);
  BIGNUM* bn_exp_x = BN_bin2bn(x, 32, nullptr);
  BIGNUM* bn_exp_y = BN_bin2bn(y, 32, nullptr);
  BIGNUM* bn_x = BN_new();
  BIGNUM* bn_y = BN_new();
  SC_CHECK_NOT_NULL(bn_d);
  SC_CHECK_NOT_NULL(bn_exp_x);
  SC_CHECK_NOT_NULL(bn_exp_y);
  SC_CHECK_SSL_OK(EC_POINT_mul(group, res, bn_d, nullptr, nullptr, nullptr));
  SC_CHECK(EC_POINT_get_affine_coordinates_GFp(group, res, bn_x, bn_y, NULL));
  SC_CHECK(BN_cmp(bn_x, bn_exp_x) == 0);
  SC_CHECK(BN_cmp(bn_y, bn_exp_y) == 0);
  EC_GROUP_free(group);
}

// At least call DeriveP256KeyFromSecret, and verify it is on the curve.
// Testing that it is hard for an attacker to guess isn't something we can
// write.
void DeriveKeyTest() {
  EC_KEY* key = DeriveP256KeyFromSecret("secrete", "purpose");
  const EC_GROUP* group = EC_KEY_get0_group(key);
  const EC_POINT* point = EC_KEY_get0_public_key(key);
  SC_CHECK(EC_POINT_is_on_curve(group, point, nullptr));
  EC_KEY_free(key);
}

// Verify we get the same key when deriving from the same secret.
void DeterministicKeyFromSecret() {
  EC_KEY* key1 = DeriveP256KeyFromSecret("secrete1", "purpose");
  EC_KEY* key2 = DeriveP256KeyFromSecret("secrete1", "purpose");
  EC_KEY* key3 = DeriveP256KeyFromSecret("secrete2", "purpose");
  const BIGNUM* key1_d = EC_KEY_get0_private_key(key1);
  const BIGNUM* key2_d = EC_KEY_get0_private_key(key2);
  const BIGNUM* key3_d = EC_KEY_get0_private_key(key3);
  SC_CHECK_EQ(BN_cmp(key1_d, key2_d), 0);
  SC_CHECK(BN_cmp(key2_d, key3_d) != 0);
  EC_KEY_free(key3);
  EC_KEY_free(key2);
  EC_KEY_free(key1);
}

}  // namespace
}  // namespace uefi_crypto
}  // namespace wasm
}  // namespace sealed

int main() {
  sealed::wasm::uefi_crypto::BaseMulTest();
  sealed::wasm::uefi_crypto::DeriveKeyTest();
  sealed::wasm::uefi_crypto::DeterministicKeyFromSecret();
  SC_LOG(INFO) << "PASSED";
  return 0;
}
