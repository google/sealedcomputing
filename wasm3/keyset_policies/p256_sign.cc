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

#include "third_party/sealedcomputing/wasm3/keyset_policies/p256_sign.h"

#include <endian.h>

#include <memory>
#include <string>
#include <vector>

#include "third_party/openssl/boringssl/src/include/openssl/bn.h"
#include "third_party/openssl/boringssl/src/include/openssl/ec.h"
#include "third_party/openssl/boringssl/src/include/openssl/ecdsa.h"
#include "third_party/openssl/boringssl/src/include/openssl/mem.h"
#include "third_party/openssl/boringssl/src/include/openssl/nid.h"
#include "third_party/sealedcomputing/wasm3/base.h"
#include "third_party/sealedcomputing/wasm3/enforcer/uefi_crypto/hkdf_sha256.h"
#include "third_party/sealedcomputing/wasm3/enforcer/uefi_crypto/p256.h"
#include "third_party/sealedcomputing/wasm3/enforcer/uefi_crypto/sha256.h"
#include "third_party/sealedcomputing/wasm3/logging.h"
#include "third_party/sealedcomputing/wasm3/status.h"

namespace sealed {
namespace wasm {
namespace {

constexpr size_t kP256PublicKeyLength = 65;
constexpr size_t kP256ScalarNbytes = 32;
constexpr size_t kP256SignatureLength = 64;

SecretByteString ComputeDigest(const ByteString& purpose,
                               const ByteString& message) {
  return uefi_crypto::Sha256(purpose + ByteString(1, '\0') + message);
}

}  // namespace

Status P256Sign::Sign(const std::string& message,
                      std::string* signature) const {
  SecretByteString quote_digest = ComputeDigest(purpose_, message);
  signature->resize(kP256SignatureLength);
  ECDSA_SIG* sig =
      ECDSA_do_sign(quote_digest.data(), quote_digest.size(), key_);
  SC_CHECK_NOT_NULL(sig);
  SC_CHECK_LE(BN_num_bytes(ECDSA_SIG_get0_r(sig)), kP256ScalarNbytes);
  SC_CHECK(kP256SignatureLength == 2 * kP256ScalarNbytes);
  signature->resize(kP256SignatureLength);
  uint8_t* sig_data = reinterpret_cast<uint8_t*>(signature->data());
  SC_CHECK_SSL_OK(
      BN_bn2bin_padded(sig_data, kP256ScalarNbytes, ECDSA_SIG_get0_r(sig)));
  SC_CHECK_LE(BN_num_bytes(ECDSA_SIG_get0_s(sig)), kP256ScalarNbytes);
  SC_CHECK_SSL_OK(BN_bn2bin_padded(sig_data + kP256ScalarNbytes,
                                   kP256ScalarNbytes, ECDSA_SIG_get0_s(sig)));
  ECDSA_SIG_free(sig);
  return Status();
}

bool P256Verify::Verify(const std::string& message,
                        const std::string& signature) const {
  SecretByteString quote_digest = ComputeDigest(purpose_, message);
  ECDSA_SIG* sig = ECDSA_SIG_new();
  const uint8_t* sig_data = reinterpret_cast<const uint8_t*>(signature.data());
  if (!ECDSA_SIG_set0(sig, BN_bin2bn(sig_data, kP256ScalarNbytes, nullptr),
                      BN_bin2bn(sig_data + kP256ScalarNbytes, kP256ScalarNbytes,
                                nullptr))) {
    ECDSA_SIG_free(sig);
    return false;
  }
  bool result =
      ECDSA_do_verify(quote_digest.data(), SHA256_DIGEST_LENGTH, sig, key_);
  ECDSA_SIG_free(sig);
  return result;
}

std::unique_ptr<P256Sign> P256Sign::Create(const std::string& purpose) {
  std::unique_ptr<P256Sign> sign(new P256Sign());
  sign->purpose_ = purpose;
  sign->key_ = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (sign->key_ == nullptr) {
    return std::unique_ptr<P256Sign>(nullptr);
  }
  if (!EC_KEY_generate_key(sign->key_)) {
    return std::unique_ptr<P256Sign>(nullptr);
  }
  return sign;
}

std::unique_ptr<P256Sign> P256Sign::CreateFromSecret(
    const SecretByteString& secret, const std::string& purpose) {
  std::unique_ptr<P256Sign> sign(new P256Sign());
  sign->purpose_ = purpose;
  // This is auto-destroyed when the last key is destroyed, using ref counting.
  constexpr char kPurpose[] = "Provisioned task signer.";
  sign->key_ = uefi_crypto::DeriveP256KeyFromSecret(secret, kPurpose);
  return sign;
}

SecretByteString P256Sign::Serialize() const {
  const BIGNUM* bignum = EC_KEY_get0_private_key(key_);
  SecretByteString output(kP256ScalarNbytes);
  SC_CHECK_SSL_OK(BN_bn2bin_padded(output.data(), kP256ScalarNbytes, bignum));
  return output;
}

void P256Verify::Serialize(std::string* output) const {
  const EC_POINT* point = EC_KEY_get0_public_key(key_);
  output->resize(kP256PublicKeyLength);
  SC_CHECK_EQ(EC_POINT_point2oct(group_, point, POINT_CONVERSION_UNCOMPRESSED,
                                 reinterpret_cast<uint8_t*>(output->data()),
                                 kP256PublicKeyLength, nullptr),
              kP256PublicKeyLength);
}

std::unique_ptr<P256Verify> P256Verify::Deserialize(
    const std::string& serialized_verifying_key, const std::string& purpose) {
  EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  SC_CHECK_NOT_NULL(group);
  EC_POINT* point = EC_POINT_new(group);
  SC_CHECK_NOT_NULL(point);
  if ((serialized_verifying_key.size() != kP256PublicKeyLength) ||
      !EC_POINT_oct2point(
          group, point,
          reinterpret_cast<const uint8_t*>(serialized_verifying_key.data()),
          kP256PublicKeyLength, nullptr)) {
    EC_POINT_free(point);
    return std::unique_ptr<P256Verify>(nullptr);
  }
  EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  EC_KEY_set_public_key(key, point);
  P256Verify* verifier = new P256Verify(key, purpose);
  EC_POINT_free(point);
  return std::unique_ptr<P256Verify>(verifier);
}

std::unique_ptr<P256Verify> P256Sign::GetVerifyingKey() const {
  EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  EC_KEY_set_public_key(key, EC_KEY_get0_public_key(key_));
  return std::unique_ptr<P256Verify>(new P256Verify(key, purpose_));
}

}  // namespace wasm
}  // namespace sealed
