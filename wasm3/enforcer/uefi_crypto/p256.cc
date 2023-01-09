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

#include "third_party/sealedcomputing/wasm3/enforcer/uefi_crypto/p256.h"

#include <stdint.h>

#include "third_party/openssl/boringssl/src/include/openssl/bn.h"
#include "third_party/openssl/boringssl/src/include/openssl/ec_key.h"
#include "third_party/openssl/boringssl/src/include/openssl/nid.h"
#include "third_party/sealedcomputing/wasm3/enforcer/uefi_crypto/hkdf_sha256.h"
#include "third_party/sealedcomputing/wasm3/enforcer/uefi_crypto/init_crypto.h"

namespace sealed {
namespace wasm {
namespace uefi_crypto {

// Derive a secret with HKDF over the secret and info with 1-byte counter
// appended.  If the derived key is >= group order, increment counter and try
// again.
EC_KEY* DeriveP256KeyFromSecret(const SecretByteString& secret,
                                const ByteString& purpose) {
  if (!global_initialized) {
    InitializeCryptoLib();
  }
  EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  const BIGNUM* order = EC_GROUP_get0_order(group);
  BIGNUM* priv = BN_new();
  uint8_t i = 0;
  do {
    SecretByteString priv_bytes =
        HkdfSha256(kP256PrivKeyBytes, secret, "", purpose + ByteString(1, i));
    i++;
    BN_bin2bn(priv_bytes.data(), priv_bytes.size(), priv);
  } while (BN_cmp(priv, order) >= 0);
  EC_KEY* key = EC_KEY_new();
  EC_KEY_set_group(key, group);
  EC_POINT* pub_point = EC_POINT_new(group);
  EC_POINT_mul(group, pub_point, priv, nullptr, nullptr, nullptr);
  SC_CHECK(EC_KEY_set_private_key(key, priv));
  SC_CHECK(EC_KEY_set_public_key(key, pub_point));
  BN_free(priv);
  EC_POINT_free(pub_point);
  return key;
}

}  // namespace uefi_crypto
}  // namespace wasm
}  // namespace sealed
