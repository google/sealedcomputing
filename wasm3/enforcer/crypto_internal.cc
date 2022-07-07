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

#include "third_party/sealedcomputing/wasm3/enforcer/crypto_internal.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include "third_party/openssl/boringssl/src/include/openssl/bn.h"
#include "third_party/openssl/boringssl/src/include/openssl/ec_key.h"
#include "third_party/openssl/boringssl/src/include/openssl/ecdsa.h"
#include "third_party/openssl/boringssl/src/include/openssl/mem.h"
#include "third_party/sealedcomputing/wasm3/base.h"
#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/crypto.h"
#include "third_party/sealedcomputing/wasm3/enforcer/uefi_crypto/aes.h"
#include "third_party/sealedcomputing/wasm3/enforcer/uefi_crypto/hkdf_sha256.h"
#include "third_party/sealedcomputing/wasm3/enforcer/uefi_crypto/p256.h"
#include "third_party/sealedcomputing/wasm3/logging.h"

namespace sealed {
namespace wasm {
namespace enforcer {

Bignum::Bignum() : bignum_(BN_new()) {
  SC_CHECK_NOT_NULL(bignum_);
  BN_zero(bignum_);
}

Bignum::Bignum(const Bignum& bignum) : bignum_(BN_dup(bignum.bignum_)) {
  SC_CHECK_NOT_NULL(bignum_);
}

Bignum::Bignum(Bignum&& bignum) {
  SC_CHECK_NOT_NULL(bignum.bignum_);
  bignum_ = bignum.bignum_;
  bignum.bignum_ = nullptr;
}

Bignum::Bignum(const uint8_t src[P256_SCALAR_NBYTES])
    : bignum_(BN_bin2bn(src, P256_SCALAR_NBYTES, nullptr)) {
  SC_CHECK_NOT_NULL(bignum_);
}

Bignum::Bignum(const ByteString& src)
    : bignum_(BN_bin2bn(src.data(), P256_SCALAR_NBYTES, nullptr)) {
  SC_CHECK_EQ(src.size(), P256_SCALAR_NBYTES);
  SC_CHECK_NOT_NULL(bignum_);
}

Bignum::Bignum(BIGNUM* bignum) : bignum_(bignum) { SC_CHECK_NOT_NULL(bignum_); }

Bignum::Bignum(const BIGNUM* bignum) : bignum_(BN_dup(bignum)) {
  SC_CHECK_NOT_NULL(bignum_);
}

Bignum::Bignum(const BIGNUM& bignum) : bignum_(BN_dup(&bignum)) {
  SC_CHECK_NOT_NULL(bignum_);
}

Bignum::Bignum(uint64_t value) : bignum_(BN_new()) {
  SC_CHECK_NOT_NULL(bignum_);
  SC_CHECK_SSL_OK(BN_set_u64(bignum_, value));
}

Bignum::~Bignum() { BN_clear_free(bignum_); }

Bignum& Bignum::operator=(const Bignum& bignum) {
  if (this != &bignum) {
    SC_CHECK_NOT_NULL(bignum.bignum_);
    BN_clear_free(bignum_);
    bignum_ = BN_dup(bignum.bignum_);
    SC_CHECK_NOT_NULL(bignum_);
  }
  return *this;
}

Bignum& Bignum::operator=(Bignum&& bignum) {
  if (this != &bignum) {
    SC_CHECK_NOT_NULL(bignum.bignum_);
    BN_clear_free(bignum_);
    bignum_ = bignum.bignum_;
    bignum.bignum_ = nullptr;
  }
  return *this;
}

EcPoint Bignum::operator*(const EcPoint& ec_point) const {
  EC_POINT* res = EC_POINT_new(ec_point.group_);
  SC_CHECK_SSL_OK(EC_POINT_mul(ec_point.group_, res, nullptr,
                               ec_point.ec_point_, bignum_, ec_point.ctx_));
  return EcPoint(res);
}
int Bignum::Cmp(const Bignum& bignum) {
  return BN_cmp(bignum_, bignum.bignum_);
}

int Bignum::Cmp(const BIGNUM* bignum) { return BN_cmp(bignum_, bignum); }

bool Bignum::operator==(const Bignum& bignum) const {
  return 1 == BN_equal_consttime(bignum_, bignum.bignum_);
}

bool Bignum::operator==(const BIGNUM* bignum) const {
  return 1 == BN_equal_consttime(bignum_, bignum);
}

bool Bignum::operator!=(const Bignum& bignum) const {
  return 0 == BN_equal_consttime(bignum_, bignum.bignum_);
}

bool Bignum::operator!=(const BIGNUM* bignum) const {
  return 0 == BN_equal_consttime(bignum_, bignum);
}

void Bignum::Serialize(uint8_t dst[P256_SCALAR_NBYTES]) const {
  SC_CHECK_SSL_OK(BN_bn2bin_padded(dst, P256_SCALAR_NBYTES, bignum_));
}

ByteString Bignum::Serialize() const {
  ByteString dst(P256_SCALAR_NBYTES);
  SC_CHECK_SSL_OK(BN_bn2bin_padded(dst.data(), P256_SCALAR_NBYTES, bignum_));
  return dst;
}

Bignum Bignum::Deserialize(const uint8_t src[P256_SCALAR_NBYTES]) {
  return Bignum(src);
}

Bignum Bignum::Deserialize(const ByteString& src) { return Bignum(src); }

Bignum Bignum::One() { return Bignum(BN_value_one()); }

Logger& operator<<(Logger& o, const Bignum& bignum) {
  ByteString bytes(BN_num_bytes(bignum.bignum_));
  return o << ByteString(BN_bn2bin(bignum.bignum_, bytes.data())).hex();
}

EcPoint::EcPoint() : ec_point_(nullptr) {}

EcPoint::EcPoint(const EcPoint& ec_point)
    : ec_point_(EC_POINT_dup(ec_point.ec_point_, group_)) {
  SC_CHECK_NOT_NULL(ec_point_);
}

EcPoint::EcPoint(EcPoint&& ec_point) {
  SC_CHECK_NOT_NULL(ec_point.ec_point_);
  ec_point_ = ec_point.ec_point_;
  ec_point.ec_point_ = nullptr;
}

// TODO(ethangertler): Elsewhere in google3, P256_NBYTES is defined to be 32,
// rather than 65.  Maybe make this constexpr uint32_t kP256PubKeyLen = 65;?
EcPoint::EcPoint(const uint8_t src[P256_NBYTES])
    : ec_point_(EC_POINT_new(group_)) {
  SC_CHECK_NOT_NULL(ec_point_);
  SC_CHECK_SSL_OK(
      EC_POINT_oct2point(group_, ec_point_, src, P256_NBYTES, ctx_));
}

EcPoint::EcPoint(const ByteString& src) : ec_point_(EC_POINT_new(group_)) {
  SC_CHECK_NOT_NULL(ec_point_);
  SC_CHECK_EQ(src.size(), P256_NBYTES);
  SC_CHECK_SSL_OK(
      EC_POINT_oct2point(group_, ec_point_, src.data(), P256_NBYTES, ctx_));
}

EcPoint::EcPoint(EC_POINT* ec_point) : ec_point_(ec_point) {
  SC_CHECK_NOT_NULL(ec_point_);
}

EcPoint::EcPoint(const EC_POINT* ec_point)
    : ec_point_(EC_POINT_dup(ec_point, group_)) {
  SC_CHECK_NOT_NULL(ec_point_);
}

EcPoint::EcPoint(const EC_POINT& ec_point)
    : ec_point_(EC_POINT_dup(&ec_point, group_)) {
  SC_CHECK_NOT_NULL(ec_point_);
}

EcPoint::~EcPoint() {
  if (ec_point_ != nullptr) {
    EC_POINT_free(ec_point_);
  }
  BN_CTX_free(ctx_);
  EC_GROUP_free(group_);
}

EcPoint& EcPoint::operator=(const EcPoint& ec_point) {
  if (this != &ec_point) {
    SC_CHECK_NOT_NULL(ec_point.ec_point_);
    if (ec_point_ != nullptr) {
      EC_POINT_free(ec_point_);
    }
    ec_point_ = EC_POINT_dup(ec_point.ec_point_, group_);
    SC_CHECK_NOT_NULL(ec_point_);
  }
  return *this;
}

EcPoint& EcPoint::operator=(EcPoint&& ec_point) {
  if (this != &ec_point) {
    SC_CHECK_NOT_NULL(ec_point.ec_point_);
    if (ec_point_ != nullptr) {
      EC_POINT_free(ec_point_);
    }
    ec_point_ = ec_point.ec_point_;
    ec_point.ec_point_ = nullptr;
  }
  return *this;
}

EcPoint EcPoint::operator+(const EcPoint& ec_point) const {
  EC_POINT* res = EC_POINT_new(group_);
  SC_CHECK_SSL_OK(
      EC_POINT_add(group_, res, this->ec_point_, ec_point.ec_point_, ctx_));
  return EcPoint(res);
}

EcPoint operator*(const EcPoint& ec_point, const Bignum& bignum) {
  EC_POINT* res = EC_POINT_new(ec_point.group_);
  SC_CHECK_SSL_OK(EC_POINT_mul(ec_point.group_, res, nullptr,
                               ec_point.ec_point_, bignum.bignum_,
                               ec_point.ctx_));
  return EcPoint(res);
}

bool EcPoint::operator==(const EcPoint& ec_point) const {
  int res = EC_POINT_cmp(group_, ec_point_, ec_point.ec_point_, ctx_);
  SC_CHECK_SSL_NO_ERR(res);
  return res == 0;
}
bool EcPoint::operator==(const EC_POINT* ec_point) const {
  int res = EC_POINT_cmp(group_, ec_point_, ec_point, ctx_);
  SC_CHECK_SSL_NO_ERR(res);
  return res == 0;
}

bool EcPoint::operator!=(const EcPoint& ec_point) const {
  int res = EC_POINT_cmp(group_, ec_point_, ec_point.ec_point_, ctx_);
  SC_CHECK_SSL_NO_ERR(res);
  return res > 0;
}
bool EcPoint::operator!=(const EC_POINT* ec_point) const {
  int res = EC_POINT_cmp(group_, ec_point_, ec_point, ctx_);
  SC_CHECK_SSL_NO_ERR(res);
  return res > 0;
}

bool EcPoint::IsValidPoint() const {
  return EC_POINT_is_on_curve(group_, ec_point_, ctx_) == 1;
}

void EcPoint::Serialize(uint8_t dst[P256_NBYTES]) const {
  SC_CHECK_EQ(P256_NBYTES, EC_POINT_point2oct(group_, ec_point_,
                                              POINT_CONVERSION_UNCOMPRESSED,
                                              dst, P256_NBYTES, ctx_));
}

ByteString EcPoint::Serialize() const {
  ByteString dst(P256_NBYTES);
  SC_CHECK_EQ(P256_NBYTES, EC_POINT_point2oct(group_, ec_point_,
                                              POINT_CONVERSION_UNCOMPRESSED,
                                              dst.data(), P256_NBYTES, ctx_));
  return dst;
}

EcPoint EcPoint::Deserialize(const uint8_t src[P256_NBYTES]) {
  return EcPoint(src);
}

EcPoint EcPoint::Deserialize(const ByteString& src) { return EcPoint(src); }

EcPoint EcPoint::BaseMul(const Bignum& bignum) {
  EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  EC_POINT* res = EC_POINT_new(group);
  SC_CHECK_SSL_OK(EC_POINT_mul(group, res, bignum.Internal_GetOpenSslBignum(),
                               nullptr, nullptr, nullptr));
  EC_GROUP_free(group);
  return EcPoint(res);
}

Logger& operator<<(Logger& o, const EcPoint& ec_point) {
  BIGNUM x, y;
  BN_init(&x);
  BN_init(&y);
  SC_CHECK_SSL_OK(EC_POINT_get_affine_coordinates(
      ec_point.group_, ec_point.ec_point_, &x, &y, ec_point.ctx_));
  return o << "Point(" << Bignum(x) << ", " << Bignum(y) << ")";
}

EcdsaSig::EcdsaSig() : sig_(nullptr) {}

void CopyEcdsaSig(const ECDSA_SIG* src, ECDSA_SIG* dst) {
  ECDSA_SIG_set0(dst, BN_dup(ECDSA_SIG_get0_r(src)),
                 BN_dup(ECDSA_SIG_get0_s(src)));
}

EcdsaSig::EcdsaSig(const EcdsaSig& sig) {
  sig_ = ECDSA_SIG_new();
  CopyEcdsaSig(sig.sig_, sig_);
  SC_CHECK_NOT_NULL(sig_);
  SC_CHECK_NE(sig_, sig.sig_);
}

EcdsaSig::EcdsaSig(EcdsaSig&& sig) {
  SC_CHECK_NOT_NULL(sig.sig_);
  sig_ = sig.sig_;
  sig.sig_ = nullptr;
}

EcdsaSig::EcdsaSig(ECDSA_SIG* sig) : sig_(sig) { SC_CHECK_NOT_NULL(sig_); }

EcdsaSig::EcdsaSig(const ECDSA_SIG* sig) {
  sig_ = ECDSA_SIG_new();
  CopyEcdsaSig(sig, sig_);
  SC_CHECK_NOT_NULL(sig_);
}
EcdsaSig::EcdsaSig(const ECDSA_SIG& sig) {
  sig_ = ECDSA_SIG_new();
  CopyEcdsaSig(&sig, sig_);
  SC_CHECK_NOT_NULL(sig_);
}

EcdsaSig::~EcdsaSig() {
  if (sig_ != nullptr) {
    ECDSA_SIG_free(sig_);
  }
}

EcdsaSig& EcdsaSig::operator=(const EcdsaSig& sig) {
  if (this != &sig) {
    SC_CHECK_NOT_NULL(sig.sig_);
    if (sig_ != nullptr) {
      ECDSA_SIG_free(sig_);
    }
    sig_ = ECDSA_SIG_new();
    CopyEcdsaSig(sig.sig_, sig_);
    SC_CHECK_NOT_NULL(sig_);
  }
  return *this;
}

EcdsaSig& EcdsaSig::operator=(EcdsaSig&& sig) {
  if (this != &sig) {
    SC_CHECK_NOT_NULL(sig.sig_);
    if (sig_ != nullptr) {
      ECDSA_SIG_free(sig_);
    }
    sig_ = sig.sig_;
    sig.sig_ = nullptr;
  }
  return *this;
}

bool EcdsaSig::Verify(const P256PublicKey& key,
                      const ByteString& digest) const {
  return ECDSA_do_verify(digest.data(), digest.size(), sig_, key.key_) == 1;
}

bool EcdsaSig::Verify(const P256PrivateKey& key,
                      const ByteString& digest) const {
  return ECDSA_do_verify(digest.data(), digest.size(), sig_, key.key_) == 1;
}

EcdsaSig EcdsaSig::Sign(const P256PrivateKey& key, const ByteString& digest) {
  ECDSA_SIG* sig = ECDSA_do_sign(digest.data(), digest.size(), key.key_);
  SC_CHECK_NOT_NULL(sig);
  return EcdsaSig(sig);
}

void EcdsaSig::Serialize(uint8_t dst[ECDSA_NBYTES]) const {
  SC_CHECK_LE(BN_num_bytes(ECDSA_SIG_get0_r(sig_)), P256_SCALAR_NBYTES);
  SC_CHECK_SSL_OK(
      BN_bn2bin_padded(dst, P256_SCALAR_NBYTES, ECDSA_SIG_get0_r(sig_)));
  SC_CHECK_LE(BN_num_bytes(ECDSA_SIG_get0_s(sig_)), P256_SCALAR_NBYTES);
  SC_CHECK_SSL_OK(BN_bn2bin_padded(dst + P256_SCALAR_NBYTES, P256_SCALAR_NBYTES,
                                   ECDSA_SIG_get0_s(sig_)));
}

ByteString EcdsaSig::Serialize() const {
  ByteString bs(ECDSA_NBYTES);
  Serialize(bs.data());
  return bs;
}

EcdsaSig EcdsaSig::Deserialize(const uint8_t src[ECDSA_NBYTES]) {
  ECDSA_SIG* sig = ECDSA_SIG_new();
  ECDSA_SIG_set0(sig, BN_bin2bn(src, P256_SCALAR_NBYTES, NULL),
                 BN_bin2bn(src + P256_SCALAR_NBYTES, P256_SCALAR_NBYTES, NULL));
  return EcdsaSig(sig);
}

EcdsaSig EcdsaSig::Deserialize(const ByteString& src) {
  return EcdsaSig::Deserialize(src.data());
}

Logger& operator<<(Logger& o, const EcdsaSig& sig) {
  const BIGNUM* out_r;
  const BIGNUM* out_s;
  ECDSA_SIG_get0(sig.sig_, &out_r, &out_s);
  Bignum r(out_r);
  Bignum s(out_s);
  return o << "EcdsaSig(" << r << ", " << s << ")";
}

P256PrivateKey::P256PrivateKey() : key_(EC_KEY_new()) {
  SC_CHECK_NOT_NULL(key_);
  SC_CHECK_SSL_OK(EC_KEY_set_group(key_, group_));
  SC_CHECK_SSL_OK(EC_KEY_generate_key_fips(key_));
  SC_CHECK_NOT_NULL(key_);
  SetPublicKey();
}

P256PrivateKey::P256PrivateKey(const P256PrivateKey& key)
    : key_(EC_KEY_dup(key.key_)) {
  SC_CHECK_NOT_NULL(key_);
}

P256PrivateKey::P256PrivateKey(P256PrivateKey&& key) {
  SC_CHECK_NOT_NULL(key.key_);
  key_ = key.key_;
  key.key_ = nullptr;
}

P256PrivateKey::P256PrivateKey(const Bignum& bignum) : key_(EC_KEY_new()) {
  SC_CHECK_NOT_NULL(key_);
  SC_CHECK_SSL_OK(EC_KEY_set_group(key_, group_));
  SC_CHECK_SSL_OK(
      EC_KEY_set_private_key(key_, bignum.Internal_GetOpenSslBignum()));
  SetPublicKey();
}

P256PrivateKey::P256PrivateKey(const BIGNUM* bignum) : key_(EC_KEY_new()) {
  SC_CHECK_NOT_NULL(key_);
  SC_CHECK_SSL_OK(EC_KEY_set_group(key_, group_));
  SC_CHECK_SSL_OK(EC_KEY_set_private_key(key_, bignum));
  SetPublicKey();
}

P256PrivateKey::P256PrivateKey(const ByteString& secret,
                               const ByteString& purpose) {
  key_ = uefi_crypto::DeriveP256KeyFromSecret(secret, purpose);
  SC_CHECK_NOT_NULL(key_);
}

P256PrivateKey::~P256PrivateKey() {
  EC_KEY_free(key_);
  BN_CTX_free(ctx_);
  EC_GROUP_free(group_);
}

P256PrivateKey& P256PrivateKey::operator=(const P256PrivateKey& key) {
  if (this != &key) {
    SC_CHECK_NOT_NULL(key.key_);
    if (key_ != nullptr) {
      EC_KEY_free(key_);
    }
    key_ = EC_KEY_dup(key.key_);
    SC_CHECK_NOT_NULL(key_);
  }
  return *this;
}

P256PrivateKey& P256PrivateKey::operator=(P256PrivateKey&& key) {
  if (this != &key) {
    SC_CHECK_NOT_NULL(key.key_);
    if (key_ != nullptr) {
      EC_KEY_free(key_);
    }
    key_ = key.key_;
    key.key_ = nullptr;
  }
  return *this;
}

bool P256PrivateKey::operator==(const P256PrivateKey& key) const {
  return GetPrivateBignum() == key.GetPrivateBignum();
}

bool P256PrivateKey::operator==(const Bignum& bignum) const {
  return GetPrivateBignum() == bignum;
}

bool P256PrivateKey::operator!=(const P256PrivateKey& key) const {
  return GetPrivateBignum() != key.GetPrivateBignum();
}

bool P256PrivateKey::operator!=(const Bignum& bignum) const {
  return GetPrivateBignum() != bignum;
}

P256PublicKey P256PrivateKey::GetPublicKey() const {
  return P256PublicKey(EC_KEY_get0_public_key(key_));
}

Bignum P256PrivateKey::GetPrivateBignum() const {
  return Bignum(EC_KEY_get0_private_key(key_));
}

EcPoint P256PrivateKey::GetPublicEcPoint() const {
  return EcPoint(EC_KEY_get0_public_key(key_));
}

EcdsaSig P256PrivateKey::EcdsaSign(const ByteString& digest) const {
  return EcdsaSig::Sign(*this, digest);
}

bool P256PrivateKey::EcdsaVerify(const ByteString& digest,
                                 const EcdsaSig& sig) const {
  return sig.Verify(*this, digest);
}

void P256PrivateKey::Serialize(uint8_t dst[P256_SCALAR_NBYTES]) const {
  GetPrivateBignum().Serialize(dst);
}

ByteString P256PrivateKey::Serialize() const {
  return GetPrivateBignum().Serialize();
}

P256PrivateKey P256PrivateKey::Deserialize(
    const uint8_t src[P256_SCALAR_NBYTES]) {
  return P256PrivateKey(Bignum(src));
}

P256PrivateKey P256PrivateKey::Deserialize(const ByteString& src) {
  return P256PrivateKey(Bignum(src));
}

void P256PrivateKey::SetPublicKey() {
  EC_POINT* point = EC_POINT_new(group_);
  SC_CHECK_NOT_NULL(point);
  SC_CHECK_SSL_OK(EC_POINT_mul(group_, point, EC_KEY_get0_private_key(key_),
                               nullptr, nullptr, ctx_));
  SC_CHECK_SSL_OK(EC_KEY_set_public_key(key_, point));
  EC_POINT_free(point);
}

Logger& operator<<(Logger& o, const P256PrivateKey& key) {
  return o << "P256PrivateKey(" << key.GetPrivateBignum() << ")";
}

P256PublicKey::P256PublicKey() : key_(nullptr) {}

P256PublicKey::P256PublicKey(const P256PublicKey& key)
    : key_(EC_KEY_dup(key.key_)) {
  SC_CHECK_NOT_NULL(key_);
}

P256PublicKey::P256PublicKey(P256PublicKey&& key) {
  SC_CHECK_NOT_NULL(key.key_);
  key_ = key.key_;
  key.key_ = nullptr;
}

P256PublicKey::P256PublicKey(const EcPoint& ec_point) : key_(EC_KEY_new()) {
  SC_CHECK_NOT_NULL(key_);
  SC_CHECK_SSL_OK(EC_KEY_set_group(key_, group_));
  SC_CHECK_SSL_OK(
      EC_KEY_set_public_key(key_, ec_point.Internal_GetOpenSslEcPoint()));
}

P256PublicKey::P256PublicKey(const EC_POINT* ec_point) : key_(EC_KEY_new()) {
  SC_CHECK_NOT_NULL(key_);
  SC_CHECK_SSL_OK(EC_KEY_set_group(key_, group_));
  SC_CHECK_SSL_OK(EC_KEY_set_public_key(key_, ec_point));
}

P256PublicKey::~P256PublicKey() {
  EC_KEY_free(key_);
  EC_GROUP_free(group_);
}

P256PublicKey& P256PublicKey::operator=(const P256PublicKey& key) {
  if (this != &key) {
    SC_CHECK_NOT_NULL(key.key_);
    if (key_ != nullptr) {
      EC_KEY_free(key_);
    }
    key_ = EC_KEY_dup(key.key_);
    SC_CHECK_NOT_NULL(key_);
  }
  return *this;
}

P256PublicKey& P256PublicKey::operator=(P256PublicKey&& key) {
  if (this != &key) {
    SC_CHECK_NOT_NULL(key.key_);
    if (key_ != nullptr) {
      EC_KEY_free(key_);
    }
    key_ = key.key_;
    key.key_ = nullptr;
  }
  return *this;
}

bool P256PublicKey::operator==(const P256PublicKey& key) const {
  return GetPublicEcPoint() == key.GetPublicEcPoint();
}

bool P256PublicKey::operator==(const EcPoint& ec_point) const {
  return GetPublicEcPoint() == ec_point;
}

bool P256PublicKey::operator!=(const P256PublicKey& key) const {
  return GetPublicEcPoint() != key.GetPublicEcPoint();
}

bool P256PublicKey::operator!=(const EcPoint& ec_point) const {
  return GetPublicEcPoint() != ec_point;
}

EcPoint P256PublicKey::GetPublicEcPoint() const {
  return EcPoint(EC_KEY_get0_public_key(key_));
}

bool P256PublicKey::EcdsaVerify(const ByteString& digest,
                                const EcdsaSig& sig) const {
  return sig.Verify(*this, digest);
}

void P256PublicKey::Serialize(uint8_t dst[P256_NBYTES]) const {
  GetPublicEcPoint().Serialize(dst);
}

ByteString P256PublicKey::Serialize() const {
  return GetPublicEcPoint().Serialize();
}

P256PublicKey P256PublicKey::Deserialize(const uint8_t src[P256_NBYTES]) {
  return P256PublicKey(EcPoint(src));
}

P256PublicKey P256PublicKey::Deserialize(const ByteString& src) {
  return P256PublicKey(EcPoint(src));
}

Logger& operator<<(Logger& o, const P256PublicKey& key) {
  return o << "P256PublicKey(" << key.GetPublicEcPoint() << ")";
}

Aes::Aes(const uint8_t key[uefi_crypto::kAes128KeyLength])
    : key_(SecretByteString(key, uefi_crypto::kAes128KeyLength)) {}

Aes::Aes(const ByteString& key) : Aes(key.data()) {
  SC_CHECK_EQ(key.size(), uefi_crypto::kAes128KeyLength);
}

Aes::Aes(const Aes& aes) {
  SC_CHECK(!aes.key_.empty());
  key_ = aes.key_;
}

Aes::Aes(Aes&& aes) {
  SC_CHECK(!aes.key_.empty());
  key_ = aes.key_;
  aes.key_.clear();
}

Aes& Aes::operator=(const Aes& aes) {
  if (this != &aes) {
    SC_CHECK(!aes.key_.empty());
    key_ = aes.key_;
  }
  return *this;
}

Aes& Aes::operator=(Aes&& aes) {
  if (this != &aes) {
    SC_CHECK(!aes.key_.empty());
    key_ = aes.key_;
  }
  return *this;
}

void Aes::EncryptBlock(const uint8_t in[uefi_crypto::kAesBlockSize],
                       uint8_t out[uefi_crypto::kAesBlockSize]) const {
  ByteString out_enc(sizeof(*out));
  uefi_crypto::AesEncryptBlock(
      key_, SecretByteString(in, uefi_crypto::kAesBlockSize), &out_enc);
  memcpy(out, out_enc.data(), out_enc.size());
}

ByteString Aes::EncryptBlock(const ByteString& in) const {
  SC_CHECK_EQ(in.size(), uefi_crypto::kAesBlockSize);
  ByteString out(uefi_crypto::kAesBlockSize);
  uefi_crypto::AesEncryptBlock(key_, in, &out);
  return out;
}

void Aes::DecryptBlock(const uint8_t in[uefi_crypto::kAesBlockSize],
                       uint8_t out[uefi_crypto::kAesBlockSize]) const {
  SecretByteString out_enc(uefi_crypto::kAesBlockSize);
  uefi_crypto::AesDecryptBlock(key_, ByteString(in, uefi_crypto::kAesBlockSize),
                               &out_enc);
  memcpy(out, out_enc.data(), uefi_crypto::kAesBlockSize);
}

SecretByteString Aes::DecryptBlock(const ByteString& in) const {
  SecretByteString out;
  uefi_crypto::AesDecryptBlock(key_, in, &out);
  return out;
}

AesGcm::AesGcm() { key_ = RandBytes(uefi_crypto::kAes128KeyLength); }

AesGcm::AesGcm(const uint8_t key[uefi_crypto::kAes128KeyLength])
    : key_(key, uefi_crypto::kAes128KeyLength) {}

AesGcm::AesGcm(const ByteString& key) : key_(key) {
  SC_CHECK_EQ(key.size(), uefi_crypto::kAes128KeyLength);
}

AesGcm::AesGcm(const AesGcm& aes_gcm) {
  SC_CHECK(!aes_gcm.key_.empty());
  key_ = aes_gcm.key_;
}

AesGcm::AesGcm(AesGcm&& aes_gcm) {
  SC_CHECK(!aes_gcm.key_.empty());
  key_ = aes_gcm.key_;
}

AesGcm& AesGcm::operator=(const AesGcm& aes_gcm) {
  SC_CHECK(!aes_gcm.key_.empty());
  key_ = aes_gcm.key_;
  return *this;
}

AesGcm& AesGcm::operator=(AesGcm&& aes_gcm) {
  SC_CHECK(!aes_gcm.key_.empty());
  key_ = aes_gcm.key_;
  return *this;
}

ByteString AesGcm::Encrypt(const uint8_t nonce[uefi_crypto::kAesGcmNonceLength],
                           const ByteString& in, const ByteString& ad) {
  return *uefi_crypto::AesGcmEncrypt(
      key_, ByteString(nonce, uefi_crypto::kAesGcmNonceLength), in, ad);
}

ByteString AesGcm::Encrypt(const ByteString& nonce, const ByteString& in,
                           const ByteString& ad) {
  return Encrypt(nonce.data(), in, ad);
}

StatusOr<SecretByteString> AesGcm::Decrypt(const ByteString& nonce,
                                           const ByteString& in,
                                           const ByteString& ad) {
  return uefi_crypto::AesGcmDecrypt(key_, nonce, in, ad);
}

StatusOr<SecretByteString> AesGcm::Decrypt(
    const uint8_t nonce[uefi_crypto::kAesGcmNonceLength], const ByteString& in,
    const ByteString& ad) {
  return Decrypt(ByteString(nonce, uefi_crypto::kAesGcmNonceLength), in, ad);
}

Sha256::Sha256() { Clear(); }

Sha256::Sha256(const ByteString& data) {
  Clear();
  Update(data);
}

void Sha256::Update(const ByteString& data) {
  if (finalized_) {
    Clear();
  }
  SC_CHECK_SSL_OK(SHA256_Update(&ctx_, data.data(), data.size()));
}

const ByteString& Sha256::Final() {
  if (!finalized_) {
    SC_CHECK_SSL_OK(SHA256_Final(digest_.data(), &ctx_));
    finalized_ = true;
  }
  return digest_;
}

void Sha256::Clear() {
  SC_CHECK_SSL_OK(SHA256_Init(&ctx_));
  finalized_ = false;
}

ByteString Sha256::Digest(const ByteString& data) {
  ByteString digest(SHA256_DIGEST_LENGTH);
  SHA256(data.data(), data.size(), digest.data());
  return digest;
}

HmacSha256::HmacSha256(const SecretByteString& key, const ByteString& data)
    : key_(key) {
  Clear();
  Update(data);
}

HmacSha256& HmacSha256::Update(const ByteString& data) {
  if (finalized_) {
    Clear();
  }
  uefi_crypto::HmacSha256Update(&ctx_, data);
  return *this;
}

const SecretByteString& HmacSha256::Final() {
  if (!finalized_) {
    digest_ = uefi_crypto::HmacSha256Final(&ctx_);
    finalized_ = true;
  }
  return digest_;
}

void HmacSha256::Clear() {
  uefi_crypto::HmacSha256Init(&ctx_, key_);
  finalized_ = false;
}

Status HmacSha256::Validate(const ByteString& expected_mac) {
  if (Final() != expected_mac) {
    return Status(kUnauthenticated, "MAC verification failed");
  }
  return Status::OkStatus();
}

SecretByteString HmacSha256::Digest(const SecretByteString& key,
                                    const ByteString& data) {
  return uefi_crypto::HmacSha256(key, data);
}

SecretByteString Hkdf(int32_t out_len, const ByteString& secret,
                      const ByteString& salt, const ByteString& info) {
  return uefi_crypto::HkdfSha256(out_len, secret, salt, info);
}

}  // namespace enforcer
}  // namespace wasm
}  // namespace sealed
