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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_CRYPTO_INTERNAL_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_CRYPTO_INTERNAL_H_

// The nicely typed external crypto calls.

#include <string>

#include "third_party/openssl/boringssl/src/include/openssl/bn.h"
#include "third_party/openssl/boringssl/src/include/openssl/ec.h"
#include "third_party/openssl/boringssl/src/include/openssl/nid.h"
#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/enforcer/uefi_crypto/aes.h"
#include "third_party/sealedcomputing/wasm3/enforcer/uefi_crypto/hmac_sha256.h"
#include "third_party/sealedcomputing/wasm3/logging.h"
#include "third_party/sealedcomputing/wasm3/statusor.h"

namespace sealed {
namespace wasm {
namespace enforcer {

#define P256_SCALAR_NBYTES 32
#define P256_NBYTES 65
#define P256_NBYTES_COMPRESSED 33
#define ECDSA_NBYTES 64

constexpr size_t kAesGcmNonceLength = uefi_crypto::kAesGcmNonceLength;
constexpr size_t kAesGcmTagLength = uefi_crypto::kAesGcmTagLength;
constexpr size_t kAes128KeyLength = uefi_crypto::kAes128KeyLength;
constexpr size_t kAes256KeyLength = uefi_crypto::kAes256KeyLength;
constexpr size_t kAesBlockSize = uefi_crypto::kAesBlockSize;
constexpr size_t kSha256DigestLength = uefi_crypto::kSha256DigestLength;
constexpr size_t kSha256CBlockLength = uefi_crypto::kSha256CBlockLength;

class EcPoint;
class P256PrivateKey;
class P256PublicKey;

class Bignum {
 public:
  Bignum();
  Bignum(const Bignum& bignum);
  Bignum(Bignum&& bignum);
  explicit Bignum(const uint8_t src[P256_SCALAR_NBYTES]);
  explicit Bignum(const ByteString& src);
  Bignum(BIGNUM* bignum);
  Bignum(const BIGNUM* bignum);
  Bignum(const BIGNUM& bignum);
  Bignum(uint64_t value);
  ~Bignum();

  Bignum& operator=(const Bignum& bignum);
  Bignum& operator=(Bignum&& bignum);

  EcPoint operator*(const EcPoint& ec_point) const;
  friend EcPoint operator*(const EcPoint& ec_point, const Bignum& bignum);
  int Cmp(const Bignum& bignum);
  int Cmp(const BIGNUM* bignum);
  bool operator==(const Bignum& bignum) const;
  bool operator==(const BIGNUM* bignum) const;
  bool operator!=(const Bignum& bignum) const;
  bool operator!=(const BIGNUM* bignum) const;
  friend Logger& operator<<(Logger& o, const Bignum& bignum);

  void Serialize(uint8_t dst[P256_SCALAR_NBYTES]) const;
  ByteString Serialize() const;
  static Bignum Deserialize(const uint8_t src[P256_SCALAR_NBYTES]);
  static Bignum Deserialize(const ByteString& src);

  static Bignum One();

  const BIGNUM* Internal_GetOpenSslBignum() const { return bignum_; }

 private:
  BIGNUM* bignum_;
};

Logger& operator<<(Logger& o, const Bignum& bignum);

class EcPoint {
 public:
  EcPoint();
  EcPoint(const EcPoint& ec_point);
  EcPoint(EcPoint&& ec_point);
  explicit EcPoint(const uint8_t src[P256_NBYTES]);
  explicit EcPoint(const ByteString& src);
  EcPoint(EC_POINT* ec_point);
  EcPoint(const EC_POINT* ec_point);
  EcPoint(const EC_POINT& ec_point);
  ~EcPoint();

  EcPoint& operator=(const EcPoint& ec_point);
  EcPoint& operator=(EcPoint&& ec_point);

  EcPoint operator+(const EcPoint& ec_point) const;
  friend EcPoint operator*(const EcPoint& ec_point, const Bignum& bignum);
  bool operator==(const EcPoint& ec_point) const;
  bool operator==(const EC_POINT* ec_point) const;
  bool operator!=(const EcPoint& ec_point) const;
  bool operator!=(const EC_POINT* ec_point) const;
  friend Logger& operator<<(Logger& o, const EcPoint& ec_point);

  bool IsValidPoint() const;

  void Serialize(uint8_t dst[P256_NBYTES]) const;
  ByteString Serialize() const;
  static StatusOr<EcPoint> Deserialize(const uint8_t src[P256_NBYTES]);
  static StatusOr<EcPoint> Deserialize(const ByteString& src);

  static EcPoint BaseMul(const Bignum& bignum);

  const EC_POINT* Internal_GetOpenSslEcPoint() const { return ec_point_; }

  friend EcPoint Bignum::operator*(const EcPoint& ec_point) const;

 private:
  BN_CTX* ctx_ = BN_CTX_new();
  EC_GROUP* group_ = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  EC_POINT* ec_point_ = nullptr;
  bool valid_ = true;
};

Logger& operator<<(Logger& o, const EcPoint& ec_point);

class EcdsaSig {
 public:
  EcdsaSig();
  EcdsaSig(const EcdsaSig& sig);
  EcdsaSig(EcdsaSig&& sig);

  // Takes ownership of `sig`.
  EcdsaSig(ECDSA_SIG* sig);

  // Does not take ownership of `sig`.
  EcdsaSig(const ECDSA_SIG* sig);
  EcdsaSig(const ECDSA_SIG& sig);

  ~EcdsaSig();

  EcdsaSig& operator=(const EcdsaSig& sig);
  EcdsaSig& operator=(EcdsaSig&& sig);
  friend Logger& operator<<(Logger& o, const EcdsaSig& sig);

  bool Verify(const P256PublicKey& key, const ByteString& digest) const;
  bool Verify(const P256PrivateKey& key, const ByteString& digest) const;

  static EcdsaSig Sign(const P256PrivateKey& key, const ByteString& digest);

  void Serialize(uint8_t dst[ECDSA_NBYTES]) const;
  ByteString Serialize() const;
  static EcdsaSig Deserialize(const uint8_t src[ECDSA_NBYTES]);
  static EcdsaSig Deserialize(const ByteString& src);

 private:
  ECDSA_SIG* sig_;
};

Logger& operator<<(Logger& o, const EcdsaSig& sig);

class P256PrivateKey {
 public:
  P256PrivateKey();
  P256PrivateKey(const P256PrivateKey& key);
  P256PrivateKey(P256PrivateKey&& key);
  P256PrivateKey(const Bignum& bignum);
  P256PrivateKey(const BIGNUM* bignum);
  P256PrivateKey(const SecretByteString& secret, const ByteString& purpose);
  ~P256PrivateKey();

  P256PrivateKey& operator=(const P256PrivateKey& key);
  P256PrivateKey& operator=(P256PrivateKey&& key);

  bool operator==(const P256PrivateKey& key) const;
  bool operator==(const Bignum& bignum) const;
  bool operator!=(const P256PrivateKey& key) const;
  bool operator!=(const Bignum& bignum) const;

  friend Logger& operator<<(Logger& o, const P256PrivateKey& key);

  P256PublicKey GetPublicKey() const;
  Bignum GetPrivateBignum() const;
  EcPoint GetPublicEcPoint() const;

  EcdsaSig EcdsaSign(const ByteString& digest) const;
  bool EcdsaVerify(const ByteString& digest, const EcdsaSig& sig) const;

  void Serialize(uint8_t dst[P256_SCALAR_NBYTES]) const;
  SecretByteString Serialize() const;
  static P256PrivateKey Deserialize(const uint8_t src[P256_SCALAR_NBYTES]);
  static P256PrivateKey Deserialize(const SecretByteString& src);

  friend bool EcdsaSig::Verify(const P256PrivateKey& key,
                               const ByteString& digest) const;
  friend EcdsaSig EcdsaSig::Sign(const P256PrivateKey& key,
                                 const ByteString& digest);

 private:
  void SetPublicKey();
  BN_CTX* ctx_ = BN_CTX_new();
  EC_GROUP* group_ = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  EC_KEY* key_;
};

Logger& operator<<(Logger& o, const P256PrivateKey& key);

class P256PublicKey {
 public:
  P256PublicKey();
  P256PublicKey(const P256PublicKey& key);
  P256PublicKey(P256PublicKey&& key);
  P256PublicKey(const EcPoint& ec_point);
  P256PublicKey(const EC_POINT* ec_point);
  ~P256PublicKey();

  P256PublicKey& operator=(const P256PublicKey& key);
  P256PublicKey& operator=(P256PublicKey&& key);

  bool operator==(const P256PublicKey& key) const;
  bool operator==(const EcPoint& ec_point) const;
  bool operator!=(const P256PublicKey& key) const;
  bool operator!=(const EcPoint& ec_point) const;

  friend Logger& operator<<(Logger& o, const P256PublicKey& key);

  EcPoint GetPublicEcPoint() const;

  bool EcdsaVerify(const ByteString& digest, const EcdsaSig& sig) const;

  void Serialize(uint8_t dst[P256_NBYTES]) const;
  ByteString Serialize() const;
  static StatusOr<P256PublicKey> Deserialize(const uint8_t src[P256_NBYTES]);
  static StatusOr<P256PublicKey> Deserialize(const ByteString& src);

  friend bool EcdsaSig::Verify(const P256PublicKey& key,
                               const ByteString& digest) const;

 private:
  EC_GROUP* group_ = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  EC_KEY* key_ = nullptr;
};

Logger& operator<<(Logger& o, const P256PublicKey& key);

class Aes {
 public:
  Aes(const uint8_t key[kAes128KeyLength]);
  Aes(const SecretByteString& key);
  Aes(const Aes& aes);
  Aes(Aes&& aes);

  Aes& operator=(const Aes& aes);
  Aes& operator=(Aes&& aes);

  void EncryptBlock(const uint8_t in[kAesBlockSize],
                    uint8_t out[kAesBlockSize]) const;
  ByteString EncryptBlock(const SecretByteString& in) const;

  void DecryptBlock(const uint8_t in[kAesBlockSize],
                    uint8_t out[kAesBlockSize]) const;
  SecretByteString DecryptBlock(const ByteString& in) const;

 private:
  SecretByteString key_;
};

class AesGcm {
 public:
  AesGcm();
  AesGcm(const uint8_t key[kAes128KeyLength]);
  AesGcm(const SecretByteString& key);
  AesGcm(const AesGcm& aes_gcm);
  AesGcm(AesGcm&& aes_gcm);

  AesGcm& operator=(const AesGcm& aes_gcm);
  AesGcm& operator=(AesGcm&& aes_gcm);

  ByteString Encrypt(const uint8_t nonce[kAesGcmNonceLength],
                     const SecretByteString& in, const ByteString& ad = "");
  ByteString Encrypt(const ByteString& nonce, const SecretByteString& in,
                     const ByteString& ad = "");

  StatusOr<SecretByteString> Decrypt(const uint8_t nonce[kAesGcmNonceLength],
                                     const ByteString& in,
                                     const ByteString& ad = "");
  StatusOr<SecretByteString> Decrypt(const ByteString& nonce,
                                     const ByteString& in,
                                     const ByteString& ad = "");

 private:
  SecretByteString key_;
};

class Sha256 {
 public:
  Sha256();
  explicit Sha256(const ByteString& data);

  void Update(const ByteString& data);
  const ByteString& Final();
  void Clear();

  static ByteString Digest(const ByteString& data);

 private:
  SHA256_CTX ctx_;
  bool finalized_ = false;
  ByteString digest_ = ByteString(SHA256_DIGEST_LENGTH);
};

class HmacSha256 {
 public:
  HmacSha256(const SecretByteString& key,
             const ByteString& data = ByteString());
  HmacSha256& Update(const ByteString& data);
  const SecretByteString& Final();
  void Clear();
  Status Validate(const ByteString& expected_mac);

  static SecretByteString Digest(const SecretByteString& key,
                                 const ByteString& data);

 private:
  SecretByteString key_;
  uefi_crypto::HmacSha256Ctx ctx_;
  bool finalized_ = false;
  SecretByteString digest_ = SecretByteString(SHA256_DIGEST_LENGTH);
};

SecretByteString Hkdf(int32_t out_len, const SecretByteString& secret,
                      const ByteString& salt, const ByteString& info);

}  // namespace enforcer
}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_CRYPTO_INTERNAL_H_
