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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_KEYSET_POLICIES_P256_SIGN_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_KEYSET_POLICIES_P256_SIGN_H_

#include <memory>

#include "third_party/openssl/boringssl/src/include/openssl/ec.h"
#include "third_party/openssl/boringssl/src/include/openssl/nid.h"
#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/keyset_policies/public_key_sign.h"
#include "third_party/sealedcomputing/wasm3/keyset_policies/public_key_verify.h"
#include "third_party/sealedcomputing/wasm3/status.h"

namespace sealed {
namespace wasm {

class P256Verify : public PublicKeyVerify {
 public:
  bool Verify(const std::string& message,
              const std::string& signature) const override;
  ~P256Verify() {
    if (key_ != nullptr) {
      EC_KEY_free(key_);
    }
  }

  // Output serialization of underlying public key. Outputs empty string on
  // error.
  void Serialize(std::string* output) const;

  static std::unique_ptr<P256Verify> Deserialize(
      const std::string& serialized_verifying_key, const std::string& purpose);

 private:
  explicit P256Verify(EC_KEY* key, const std::string& purpose)
      : key_(key), purpose_(purpose) {}
  EC_GROUP* group_ = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  // key_ is owned by instances of this class.
  EC_KEY* key_ = nullptr;
  std::string purpose_;

  friend class P256Sign;
};

class P256Sign : public PublicKeySign {
 public:
  static std::unique_ptr<P256Sign> Create(const std::string& purpose);
  static std::unique_ptr<P256Sign> CreateFromSecret(
      const SecretByteString& secret, const std::string& purpose);
  ~P256Sign() {
    if (key_ != nullptr) {
      EC_KEY_free(key_);
    }
  }

  // Return value is an ECDSA P-256 signature over the SHA256 digest of
  // |purpose_length| (32 bits, little-endian)
  // |purpose_|,
  // |message|.
  Status Sign(const std::string& message,
              std::string* signature) const override;

  std::unique_ptr<P256Verify> GetVerifyingKey() const;

 private:
  EC_KEY* key_ = nullptr;
  std::string purpose_;
};

}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_KEYSET_POLICIES_P256_SIGN_H_
