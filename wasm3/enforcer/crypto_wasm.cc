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

#include "third_party/sealedcomputing/wasm3/builtin/crypto_wasm.h"

#include <time.h>

#include <cstdint>
#include <cstring>
#include <memory>

#include "third_party/openssl/boringssl/src/include/openssl/bn.h"
#include "third_party/openssl/boringssl/src/include/openssl/curve25519.h"
#include "third_party/openssl/boringssl/src/include/openssl/ec.h"
#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/cprng.h"
#include "third_party/sealedcomputing/wasm3/enforcer/builtin_impl.h"
#include "third_party/sealedcomputing/wasm3/enforcer/crypto_internal.h"
#include "third_party/sealedcomputing/wasm3/enforcer/hybrid_encryption.h"
#include "third_party/sealedcomputing/wasm3/enforcer/slab.h"
#include "third_party/sealedcomputing/wasm3/enforcer/trng.h"
#include "third_party/sealedcomputing/wasm3/enforcer/uefi_crypto/aes.h"
#include "third_party/sealedcomputing/wasm3/enforcer/wasm.h"
#include "third_party/sealedcomputing/wasm3/keyset_policies/emulated_sealer.h"
#include "third_party/sealedcomputing/wasm3/keyset_policies/sealer.h"
#include "third_party/sealedcomputing/wasm3/keyset_policies/task_sealer.h"
#include "third_party/sealedcomputing/wasm3/status.h"

namespace sealed {
namespace wasm {
namespace enforcer {

namespace {

// Forward declaration.
void InitGlobals();

bool globals_initialized = false;

inline void InitGlobalsIfNeeded() {
  if (!globals_initialized) {
    InitGlobals();
  }
}

typedef Slab<enforcer::Sha256> Sha256Slab;
typedef Sha256Slab::SlabPtr Sha256Ptr;
Sha256Slab* sha_slab = nullptr;

typedef Slab<enforcer::HmacSha256> HmacSha256Slab;
typedef HmacSha256Slab::SlabPtr HmacSha256Ptr;
HmacSha256Slab* hmac_slab = nullptr;

typedef Slab<Bignum> BignumSlab;
typedef BignumSlab::SlabPtr BignumPtr;
BignumSlab* bignum_slab = nullptr;

typedef Slab<EcPoint> EcPointSlab;
typedef EcPointSlab::SlabPtr EcPointPtr;
EcPointSlab* ec_point_slab = nullptr;

typedef Slab<P256PrivateKey> P256PrivateKeySlab;
typedef P256PrivateKeySlab::SlabPtr P256PrivateKeyPtr;
P256PrivateKeySlab* private_key_slab = nullptr;

typedef Slab<P256PublicKey> P256PublicKeySlab;
typedef P256PublicKeySlab::SlabPtr P256PublicKeyPtr;
P256PublicKeySlab* public_key_slab = nullptr;

typedef Slab<EcdsaSig> EcdsaSigSlab;
typedef EcdsaSigSlab::SlabPtr EcdsaSigPtr;
EcdsaSigSlab* ecdsa_sig_slab = nullptr;

typedef Slab<Aes> AesSlab;
typedef AesSlab::SlabPtr AesPtr;
AesSlab* aes_slab = nullptr;

typedef Slab<AesGcm> AesGcmSlab;
typedef AesGcmSlab::SlabPtr AesGcmPtr;
AesGcmSlab* aes_gcm_slab = nullptr;

typedef Slab<EciesX25519PrivateKey> EciesX25519PrivateKeySlab;
typedef EciesX25519PrivateKeySlab::SlabPtr EciesX25519PrivateKeyPtr;
EciesX25519PrivateKeySlab* ecies_x25519_privkey_slab = nullptr;

typedef Slab<EciesX25519PublicKey> EciesX25519PublicKeySlab;
typedef EciesX25519PublicKeySlab::SlabPtr EciesX25519PublicKeyPtr;
EciesX25519PublicKeySlab* ecies_x25519_pubkey_slab = nullptr;

typedef Slab<EciesP256PublicKey> EciesP256PublicKeySlab;
typedef EciesP256PublicKeySlab::SlabPtr EciesP256PublicKeyPtr;
EciesP256PublicKeySlab* ecies_p256_pubkey_slab = nullptr;

// Used for generating cryptographically secure pseudo-random bytes.
Cprng* global_cprng = nullptr;
// These constants are used to figure out how often we can reseed.
constexpr size_t kRdrandCallsPerReseed = kSha256DigestLength / sizeof(uint32_t);
constexpr size_t kRdrandCycles = 1200 * kRdrandCallsPerReseed;
constexpr size_t kDesiredRdrandAverageCycles = 10;
constexpr size_t kRdrandReseedThreshold =
    kRdrandCycles / kDesiredRdrandAverageCycles;

void SeedGlobalCprng() {
  SC_CHECK_NOT_NULL(global_cprng);
  SecretByteString trng_seed(kSha256DigestLength);
  for (size_t i = 0; i < kRdrandCallsPerReseed; i++) {
    uint32_t rand_val = rand32();
    memcpy(trng_seed.data() + i * sizeof(uint32_t), &rand_val,
           sizeof(uint32_t));
  }
  struct timespec tp;
  clock_gettime(CLOCK_MONOTONIC, &tp);
  SecretByteString time(reinterpret_cast<char*>(&tp), sizeof(tp));
  global_cprng->Seed(trng_seed + time);
}

}  // namespace

extern "C" {

biOpaqueBignum biBignumFromBin(const biBignum src) {
  InitGlobalsIfNeeded();
  Bignum bignum = Bignum::Deserialize(reinterpret_cast<const uint8_t*>(src));
  return bignum_slab->Create(bignum).Serialize();
}

void biBignumToBin(biOpaqueBignum bignum, biBignum dst) {
  InitGlobalsIfNeeded();
  const Bignum* src = bignum_slab->Get(bignum);
  src->Serialize(reinterpret_cast<uint8_t*>(dst));
}

void biDestroyBignum(biOpaqueBignum bignum) {
  InitGlobalsIfNeeded();
  bignum_slab->Destroy(bignum);
}

biOpaqueBignum biBignumOne(void) {
  InitGlobalsIfNeeded();
  return bignum_slab->Create(Bignum::One()).Serialize();
}

biOpaqueP256Point biP256PointFromBin(const biP256Point src) {
  InitGlobalsIfNeeded();
  StatusOr<EcPoint> ec_point =
      EcPoint::Deserialize(reinterpret_cast<const uint8_t*>(src));
  // TODO(b/253542945): replace with sealed RPC which returns non-OK status.
  SC_CHECK_OK(ec_point);
  return ec_point_slab->Create(*ec_point).Serialize();
}

void biP256PointToBin(biOpaqueP256Point ec_point, biP256Point dst) {
  InitGlobalsIfNeeded();
  const EcPoint* src = ec_point_slab->Get(ec_point);
  src->Serialize(reinterpret_cast<uint8_t*>(dst));
}

void biP256PointRaw(biOpaqueP256Point ec_point, biP256Point dst) {
  InitGlobalsIfNeeded();
  const EcPoint* src = ec_point_slab->Get(ec_point);
  src->Serialize(reinterpret_cast<uint8_t*>(dst));
}

void biDestroyPoint(biOpaqueP256Point ec_point) {
  InitGlobalsIfNeeded();
  ec_point_slab->Destroy(ec_point);
}

m3ApiRawFunction(biP256PrivateKeyFromBin_wrapper) {
  m3ApiReturnType(biOpaqueP256PrivateKey);
  m3ApiGetArgMem(biBignum, src);
  SC_CHECK(MemCheckRange(src, P256_SCALAR_NBYTES));
  biOpaqueP256PrivateKey result = biP256PrivateKeyFromBin(src);
  m3ApiReturn(result);
}

biOpaqueP256PrivateKey biP256PrivateKeyFromBin(const biBignum src) {
  InitGlobalsIfNeeded();
  P256PrivateKey key =
      P256PrivateKey::Deserialize(reinterpret_cast<const uint8_t*>(src));
  return private_key_slab->Create(key).Serialize();
}

m3ApiRawFunction(biP256PrivateKeyToBin_wrapper) {
  m3ApiGetArg(biOpaqueP256PrivateKey, key);
  m3ApiGetArgMem(biBignum, dst);
  SC_CHECK(MemCheckRange(dst, P256_SCALAR_NBYTES));
  biP256PrivateKeyToBin(key, dst);
  m3ApiSuccess();
}

void biP256PrivateKeyToBin(biOpaqueP256PrivateKey key, biBignum dst) {
  InitGlobalsIfNeeded();
  const P256PrivateKey* src = private_key_slab->Get(key);
  src->Serialize(reinterpret_cast<uint8_t*>(dst));
}

m3ApiRawFunction(biDestroyP256PrivateKey_wrapper) {
  m3ApiGetArg(biOpaqueP256PrivateKey, src);
  biDestroyP256PrivateKey(src);
  m3ApiSuccess();
}

void biDestroyP256PrivateKey(biOpaqueP256PrivateKey src) {
  InitGlobalsIfNeeded();
  private_key_slab->Destroy(src);
}

m3ApiRawFunction(biP256PublicKeyFromBin_wrapper) {
  m3ApiReturnType(biOpaqueP256PublicKey);
  m3ApiGetArgMem(biP256Point, src);
  SC_CHECK(MemCheckRange(src, P256_NBYTES));
  biOpaqueP256PublicKey result = biP256PublicKeyFromBin(src);
  m3ApiReturn(result);
}

biOpaqueP256PublicKey biP256PublicKeyFromBin(const biP256Point src) {
  InitGlobalsIfNeeded();
  StatusOr<P256PublicKey> key =
      P256PublicKey::Deserialize(reinterpret_cast<const uint8_t*>(src));
  // TODO(b/253542945): replace with sealed RPC which returns non-OK status.
  SC_CHECK_OK(key);
  return public_key_slab->Create(*key).Serialize();
}

m3ApiRawFunction(biP256PublicKeyFromPrivateKey_wrapper) {
  m3ApiReturnType(biOpaqueP256PublicKey);
  m3ApiGetArg(biOpaqueP256PrivateKey, key);
  biOpaqueP256PublicKey result = biP256PublicKeyFromPrivateKey(key);
  m3ApiReturn(result);
}

biOpaqueP256PublicKey biP256PublicKeyFromPrivateKey(
    biOpaqueP256PrivateKey key) {
  InitGlobalsIfNeeded();
  const P256PrivateKey* src = private_key_slab->Get(key);
  return public_key_slab->Create(src->GetPublicKey()).Serialize();
}

m3ApiRawFunction(biP256PublicKeyToBin_wrapper) {
  m3ApiGetArg(biOpaqueP256PublicKey, key);
  m3ApiGetArgMem(biP256Point, dst);
  SC_CHECK(MemCheckRange(dst, P256_NBYTES));
  biP256PublicKeyToBin(key, dst);
  m3ApiSuccess();
}

void biP256PublicKeyToBin(biOpaqueP256PublicKey key, biP256Point dst) {
  InitGlobalsIfNeeded();
  const P256PublicKey* src = public_key_slab->Get(key);
  src->Serialize(reinterpret_cast<uint8_t*>(dst));
}

m3ApiRawFunction(biDestroyP256PublicKey_wrapper) {
  m3ApiGetArg(biOpaqueP256PublicKey, src);
  biDestroyP256PublicKey(src);
  m3ApiSuccess();
}

void biDestroyP256PublicKey(biOpaqueP256PublicKey src) {
  InitGlobalsIfNeeded();
  public_key_slab->Destroy(src);
}

m3ApiRawFunction(biEcdsaSigFromBin_wrapper) {
  m3ApiReturnType(biOpaqueEcdsaSig);
  m3ApiGetArgMem(const biEcdsaSig, src);
  SC_CHECK(MemCheckRange(src, ECDSA_NBYTES));
  biOpaqueEcdsaSig result = biEcdsaSigFromBin(src);
  m3ApiReturn(result);
}

biOpaqueEcdsaSig biEcdsaSigFromBin(const biEcdsaSig src) {
  InitGlobalsIfNeeded();
  EcdsaSig sig = EcdsaSig::Deserialize(reinterpret_cast<const uint8_t*>(src));
  return ecdsa_sig_slab->Create(sig).Serialize();
}

m3ApiRawFunction(biEcdsaSigToBin_wrapper) {
  m3ApiGetArg(biOpaqueEcdsaSig, sig);
  m3ApiGetArgMem(biEcdsaSig, dst);
  SC_CHECK(MemCheckRange(dst, ECDSA_NBYTES));
  biEcdsaSigToBin(sig, dst);
  m3ApiSuccess();
}

void biEcdsaSigToBin(biOpaqueEcdsaSig sig, biEcdsaSig dst) {
  InitGlobalsIfNeeded();
  const EcdsaSig* src = ecdsa_sig_slab->Get(sig);
  src->Serialize(reinterpret_cast<uint8_t*>(dst));
}

m3ApiRawFunction(biDestroyEcdsaSig_wrapper) {
  m3ApiGetArg(biOpaqueEcdsaSig, src);
  biDestroyEcdsaSig(src);
  m3ApiSuccess();
}

void biDestroyEcdsaSig(biOpaqueEcdsaSig src) {
  InitGlobalsIfNeeded();
  ecdsa_sig_slab->Destroy(src);
}

m3ApiRawFunction(biAesKeyFromBin_wrapper) {
  m3ApiReturnType(biOpaqueAesKey);
  m3ApiGetArgMem(const biAesKey, src);
  SC_CHECK(MemCheckRange(src, uefi_crypto::kAes128KeyLength));
  biOpaqueAesKey result = biAesKeyFromBin(src);
  m3ApiReturn(result);
}

biOpaqueAesKey biAesKeyFromBin(const biAesKey src) {
  InitGlobalsIfNeeded();
  Aes aes(reinterpret_cast<const uint8_t*>(src));
  return aes_slab->Create(aes).Serialize();
}

void biDestroyAesKey(biOpaqueAesKey key) {
  InitGlobalsIfNeeded();
  aes_slab->Destroy(key);
}

m3ApiRawFunction(biAesGcmKeyFromBin_wrapper) {
  m3ApiReturnType(biOpaqueAesGcmKey);
  m3ApiGetArgMem(const biAesGcmKey, src);
  SC_CHECK(MemCheckRange(src, uefi_crypto::kAes128KeyLength));
  biOpaqueAesGcmKey result = biAesGcmKeyFromBin(src);
  m3ApiReturn(result);
}

biOpaqueAesGcmKey biAesGcmKeyFromBin(const biAesGcmKey src) {
  InitGlobalsIfNeeded();
  AesGcm aes_gcm(reinterpret_cast<const uint8_t*>(src));
  return aes_gcm_slab->Create(aes_gcm).Serialize();
}

m3ApiRawFunction(biDestroyAesGcmKey_wrapper) {
  m3ApiGetArg(biOpaqueAesGcmKey, key);
  biDestroyAesGcmKey(key);
  m3ApiSuccess();
}

void biDestroyAesGcmKey(biOpaqueAesGcmKey key) {
  InitGlobalsIfNeeded();
  aes_gcm_slab->Destroy(key);
}

m3ApiRawFunction(biGenP256PrivateKey_wrapper) {
  m3ApiReturnType(biOpaqueP256PrivateKey);
  biOpaqueP256PrivateKey result = biGenP256PrivateKey();
  m3ApiReturn(result);
}

biOpaqueP256PrivateKey biGenP256PrivateKey(void) {
  InitGlobalsIfNeeded();
  return private_key_slab->Create(new P256PrivateKey()).Serialize();
}

biOpaqueP256Point biP256BasePointMul(biOpaqueBignum n) {
  InitGlobalsIfNeeded();
  const Bignum* bignum = bignum_slab->Get(n);
  return ec_point_slab->Create(EcPoint::BaseMul(*bignum)).Serialize();
}

biOpaqueP256Point biP256PointMul(biOpaqueBignum n, biOpaqueP256Point ec_point) {
  InitGlobalsIfNeeded();
  const Bignum* bignum = bignum_slab->Get(n);
  const EcPoint* pt = ec_point_slab->Get(ec_point);
  return ec_point_slab->Create(*bignum * *pt).Serialize();
}

m3ApiRawFunction(biP256EcdsaSign_wrapper) {
  m3ApiReturnType(biOpaqueEcdsaSig);
  m3ApiGetArg(biOpaqueP256PrivateKey, key);
  m3ApiGetArgMem(const void*, digest);
  m3ApiGetArg(int32_t, digest_len);
  SC_CHECK(MemCheckRange(digest, digest_len));
  biOpaqueEcdsaSig result = biP256EcdsaSign(key, digest, digest_len);
  m3ApiReturn(result);
}

biOpaqueEcdsaSig biP256EcdsaSign(biOpaqueP256PrivateKey key, const void* digest,
                                 int32_t digest_len) {
  InitGlobalsIfNeeded();
  const P256PrivateKey* private_key = private_key_slab->Get(key);
  ByteString dgt(digest, digest_len);
  return ecdsa_sig_slab->Create(private_key->EcdsaSign(dgt)).Serialize();
}

// TODO(b/218719513): Write a unit test for passing a bad pointer for digest.
m3ApiRawFunction(biP256EcdsaVerify_wrapper) {
  m3ApiReturnType(biBool);
  m3ApiGetArg(biOpaqueP256PublicKey, key);
  m3ApiGetArgMem(const void*, digest);
  m3ApiGetArg(int32_t, digest_len);
  m3ApiGetArg(biOpaqueEcdsaSig, sig);
  SC_CHECK(MemCheckRange(digest, digest_len));
  biBool result = biP256EcdsaVerify(key, digest, digest_len, sig);
  m3ApiReturn(result);
}

biBool biP256EcdsaVerify(biOpaqueP256PublicKey key, const void* digest,
                         int32_t digest_len, biOpaqueEcdsaSig sig) {
  InitGlobalsIfNeeded();
  const P256PublicKey* public_key = public_key_slab->Get(key);
  ByteString dgt(digest, digest_len);
  EcdsaSig* ecdsa_sig = ecdsa_sig_slab->Get(sig);
  return public_key->EcdsaVerify(dgt, *ecdsa_sig);
}

biBool biP256IsValidPoint(biOpaqueP256Point ec_point) {
  InitGlobalsIfNeeded();
  const EcPoint* pt = ec_point_slab->Get(ec_point);
  return pt->IsValidPoint();
}

m3ApiRawFunction(biEncryptAesBlock_wrapper) {
  m3ApiGetArg(biOpaqueAesKey, aes_key);
  m3ApiGetArgMem(const biAesBlock, in);
  m3ApiGetArgMem(biAesBlock, out);
  SC_CHECK(MemCheckRange(in, uefi_crypto::kAesBlockSize));
  SC_CHECK(MemCheckRange(out, uefi_crypto::kAesBlockSize));
  biEncryptAesBlock(aes_key, in, out);
  m3ApiSuccess();
}

void biEncryptAesBlock(biOpaqueAesKey aes_key, const biAesBlock in,
                       biAesBlock out) {
  InitGlobalsIfNeeded();
  Aes* aes = aes_slab->Get(aes_key);
  aes->EncryptBlock(static_cast<const uint8_t*>(in),
                    static_cast<uint8_t*>(out));
}

m3ApiRawFunction(biDecryptAesBlock_wrapper) {
  m3ApiGetArg(biOpaqueAesKey, aes_key);
  m3ApiGetArgMem(const biAesBlock, in);
  m3ApiGetArgMem(biAesBlock, out);
  SC_CHECK(MemCheckRange(in, uefi_crypto::kAesBlockSize));
  SC_CHECK(MemCheckRange(out, uefi_crypto::kAesBlockSize));
  biDecryptAesBlock(aes_key, in, out);
  m3ApiSuccess();
}

void biDecryptAesBlock(biOpaqueAesKey aes_key, const biAesBlock in,
                       biAesBlock out) {
  InitGlobalsIfNeeded();
  Aes* aes = aes_slab->Get(aes_key);
  aes->DecryptBlock(static_cast<const uint8_t*>(in),
                    static_cast<uint8_t*>(out));
}

m3ApiRawFunction(biAesGcmEncrypt_wrapper) {
  m3ApiGetArg(biOpaqueAesGcmKey, key);
  m3ApiGetArgMem(const void*, nonce);
  m3ApiGetArgMem(const void*, in);
  m3ApiGetArg(int32_t, in_len);
  m3ApiGetArgMem(const void*, ad);
  m3ApiGetArg(int32_t, ad_len);
  m3ApiGetArgMem(void*, out);
  m3ApiGetArgMem(void*, out_len);
  SC_CHECK(MemCheckRange(nonce, uefi_crypto::kAesGcmNonceLength));
  SC_CHECK(MemCheckRange(in, in_len));
  SC_CHECK(MemCheckRange(ad, ad_len));
  SC_CHECK(MemCheckRange(out, in_len + uefi_crypto::kAesGcmTagLength));
  SC_CHECK(MemCheckRange(out_len, sizeof(uint32_t)));
  biAesGcmEncrypt(key, nonce, in, in_len, ad, ad_len, out, out_len);
  m3ApiSuccess();
}

void biAesGcmEncrypt(biOpaqueAesGcmKey key, const void* nonce, const void* in,
                     int32_t in_len, const void* ad, int32_t ad_len, void* out,
                     void* out_len) {
  InitGlobalsIfNeeded();
  AesGcm* aes_gcm = aes_gcm_slab->Get(key);
  ByteString in_str(in, in_len);
  ByteString ad_str(ad, ad_len);
  ByteString out_str =
      aes_gcm->Encrypt(static_cast<const uint8_t*>(nonce), in_str, ad_str);
  memcpy(out, out_str.data(), out_str.size());
  *static_cast<uint32_t*>(out_len) = out_str.size();
}

m3ApiRawFunction(biAesGcmDecrypt_wrapper) {
  m3ApiGetArg(biOpaqueAesGcmKey, key);
  m3ApiGetArgMem(const void*, nonce);
  m3ApiGetArgMem(const void*, in);
  m3ApiGetArg(int32_t, in_len);
  m3ApiGetArgMem(const void*, ad);
  m3ApiGetArg(int32_t, ad_len);
  m3ApiGetArgMem(void*, out);
  m3ApiGetArgMem(void*, out_len);
  SC_CHECK(MemCheckRange(nonce, uefi_crypto::kAesGcmNonceLength));
  SC_CHECK(MemCheckRange(in, in_len));
  SC_CHECK(MemCheckRange(ad, ad_len));
  SC_CHECK(MemCheckRange(out, in_len + uefi_crypto::kAesGcmTagLength));
  SC_CHECK(MemCheckRange(out_len, sizeof(uint32_t)));
  biAesGcmDecrypt(key, nonce, in, in_len, ad, ad_len, out, out_len);
  m3ApiSuccess();
}

void biAesGcmDecrypt(biOpaqueAesGcmKey key, const void* nonce, const void* in,
                     int32_t in_len, const void* ad, int32_t ad_len, void* out,
                     void* out_len) {
  InitGlobalsIfNeeded();
  AesGcm* aes_gcm = aes_gcm_slab->Get(key);
  ByteString in_str(in, in_len);
  ByteString ad_str(ad, ad_len);
  StatusOr<SecretByteString> result =
      aes_gcm->Decrypt(static_cast<const uint8_t*>(nonce), in_str, ad_str);
  SC_CHECK(result.ok());
  memcpy(out, reinterpret_cast<const uint8_t*>(result->data()), result->size());
  *static_cast<uint32_t*>(out_len) = result->size();
}

m3ApiRawFunction(biSha256_wrapper) {
  m3ApiGetArgMem(const void*, data);
  m3ApiGetArg(biSizeT, data_len);
  m3ApiGetArgMem(biSha256Digest, digest);
  SC_CHECK(MemCheckRange(data, data_len));
  SC_CHECK(MemCheckRange(digest, SHA256_DIGEST_LENGTH));
  biSha256(data, data_len, digest);
  m3ApiSuccess();
}

void biSha256(const void* data, biSizeT data_len, biSha256Digest digest) {
  ByteString data_str(data, data_len);
  ByteString digest_str = Sha256::Digest(data_str);
  memcpy(digest, digest_str.data(), SHA256_DIGEST_LENGTH);
}

m3ApiRawFunction(biSha256init_wrapper) {
  m3ApiReturnType(biOpaqueSha256);
  biOpaqueSha256 result = biSha256init();
  m3ApiReturn(result);
}

biOpaqueSha256 biSha256init() {
  InitGlobalsIfNeeded();
  return sha_slab->Create(new Sha256()).Serialize();
}

m3ApiRawFunction(biSha256update_wrapper) {
  m3ApiGetArg(biOpaqueSha256, opaque_sha);
  m3ApiGetArgMem(const void*, data);
  m3ApiGetArg(int32_t, data_len);
  SC_CHECK(MemCheckRange(data, data_len));
  biSha256update(opaque_sha, data, data_len);
  m3ApiSuccess();
}

void biSha256update(biOpaqueSha256 opaque_sha, const void* data,
                    int32_t data_len) {
  InitGlobalsIfNeeded();
  Sha256* sha = sha_slab->Get(opaque_sha);
  ByteString data_str(data, data_len);
  sha->Update(data_str);
}

m3ApiRawFunction(biSha256final_wrapper) {
  m3ApiGetArg(biOpaqueSha256, opaque_sha);
  m3ApiGetArgMem(biSha256Digest, digest);
  SC_CHECK(MemCheckRange(digest, SHA256_DIGEST_LENGTH));
  biSha256final(opaque_sha, digest);
  m3ApiSuccess();
}

void biSha256final(biOpaqueSha256 opaque_sha, biSha256Digest digest) {
  InitGlobalsIfNeeded();
  Sha256* sha = sha_slab->Get(opaque_sha);
  ByteString digest_str = sha->Final();
  memcpy(digest, digest_str.data(), SHA256_DIGEST_LENGTH);
  sha_slab->Destroy(opaque_sha);
}

m3ApiRawFunction(biHmacSha256_wrapper) {
  m3ApiGetArgMem(const void*, key);
  m3ApiGetArg(biSizeT, key_len);
  m3ApiGetArgMem(const void*, data);
  m3ApiGetArg(biSizeT, data_len);
  m3ApiGetArgMem(biSha256Digest, digest);
  SC_CHECK(MemCheckRange(key, key_len));
  SC_CHECK(MemCheckRange(data, data_len));
  SC_CHECK(MemCheckRange(digest, SHA256_DIGEST_LENGTH));
  biHmacSha256(key, key_len, data, data_len, digest);
  m3ApiSuccess();
}

void biHmacSha256(const void* key, biSizeT key_len, const void* data,
                  biSizeT data_len, biSha256Digest digest) {
  SecretByteString key_str(key, key_len);
  ByteString data_str(data, data_len);
  ByteString digest_str = HmacSha256::Digest(key_str, data_str);
  memcpy(digest, digest_str.data(), SHA256_DIGEST_LENGTH);
}

m3ApiRawFunction(biHmacSha256init_wrapper) {
  m3ApiReturnType(biOpaqueHmac);
  m3ApiGetArgMem(const void*, key);
  m3ApiGetArg(biSizeT, key_len);
  SC_CHECK(MemCheckRange(key, key_len));
  biOpaqueHmac result = biHmacSha256init(key, key_len);
  m3ApiReturn(result);
}

biOpaqueHmac biHmacSha256init(const void* key, biSizeT key_len) {
  InitGlobalsIfNeeded();
  SecretByteString key_str(key, key_len);
  return hmac_slab->Create(new HmacSha256(key_str)).Serialize();
}

m3ApiRawFunction(biHmacSha256update_wrapper) {
  m3ApiGetArg(biOpaqueHmac, opaque_hmac);
  m3ApiGetArgMem(const void*, data);
  m3ApiGetArg(biSizeT, data_len);
  SC_CHECK(MemCheckRange(data, data_len));
  biHmacSha256update(opaque_hmac, data, data_len);
  m3ApiSuccess();
}

void biHmacSha256update(biOpaqueHmac opaque_hmac, const void* data,
                        biSizeT data_len) {
  InitGlobalsIfNeeded();
  HmacSha256* hmac = hmac_slab->Get(opaque_hmac);
  ByteString data_str(data, data_len);
  hmac->Update(data_str);
}

m3ApiRawFunction(biHmacSha256final_wrapper) {
  m3ApiGetArg(biOpaqueHmac, opaque_hmac);
  m3ApiGetArgMem(biSha256Digest, digest);
  SC_CHECK(MemCheckRange(digest, SHA256_DIGEST_LENGTH));
  biHmacSha256final(opaque_hmac, digest);
  m3ApiSuccess();
}

void biHmacSha256final(biOpaqueHmac opaque_hmac, biSha256Digest digest) {
  InitGlobalsIfNeeded();
  HmacSha256* hmac = hmac_slab->Get(opaque_hmac);
  ByteString digest_str = hmac->Final();
  memcpy(digest, digest_str.data(), SHA256_DIGEST_LENGTH);
  hmac_slab->Destroy(opaque_hmac);
}

m3ApiRawFunction(biHkdf_wrapper) {
  m3ApiGetArg(int32_t, out_len);
  m3ApiGetArgMem(const void*, secret);
  m3ApiGetArg(int32_t, secret_len);
  m3ApiGetArgMem(const void*, salt);
  m3ApiGetArg(int32_t, salt_len);
  m3ApiGetArgMem(const void*, info);
  m3ApiGetArg(int32_t, info_len);
  m3ApiGetArgMem(void*, out_key);
  SC_CHECK(MemCheckRange(secret, secret_len));
  SC_CHECK(MemCheckRange(salt, salt_len));
  SC_CHECK(MemCheckRange(info, info_len));
  SC_CHECK(MemCheckRange(out_key, out_len));
  biHkdf(out_len, secret, secret_len, salt, salt_len, info, info_len, out_key);
  m3ApiSuccess();
}

void biHkdf(int32_t out_len, const void* secret, int32_t secret_len,
            const void* salt, int32_t salt_len, const void* info,
            int32_t info_len, void* out_key) {
  ByteString secret_str(secret, secret_len);
  ByteString salt_str(salt, salt_len);
  ByteString info_str(info, info_len);
  ByteString out_str = Hkdf(out_len, secret_str, salt_str, info_str);
  memcpy(out_key, out_str.data(), out_len);
}

m3ApiRawFunction(biRandBytes_wrapper) {
  m3ApiGetArgMem(void*, buf);
  m3ApiGetArg(int32_t, len);
  SC_CHECK(MemCheckRange(buf, len));
  biRandBytes(buf, len);
  m3ApiSuccess();
}

void biRandBytes(void* buf, int32_t len) {
  InitGlobalsIfNeeded();
  static size_t bytes_since_reseed = 0;
  SC_CHECK_NOT_NULL(global_cprng);
  if (bytes_since_reseed >= kRdrandReseedThreshold * sizeof(uint32_t)) {
    SeedGlobalCprng();
    bytes_since_reseed = 0;
  }
  SecretByteString bytes = global_cprng->RandBytes(len);
  memcpy(buf, bytes.data(), len);
  bytes_since_reseed += len;
}

m3ApiRawFunction(biGenEciesX25519PrivateKey_wrapper) {
  m3ApiReturnType(biOpaqueEciesX25519PrivateKey);
  biOpaqueEciesX25519PrivateKey privkey = biGenEciesX25519PrivateKey();
  m3ApiReturn(privkey);
}

biOpaqueEciesX25519PrivateKey biGenEciesX25519PrivateKey() {
  InitGlobalsIfNeeded();
  SecretByteString secret(X25519_PRIVATE_KEY_LEN);
  biRandBytes(secret.data(), secret.size());
  return ecies_x25519_privkey_slab->Create(new EciesX25519PrivateKey(secret))
      .Serialize();
}

m3ApiRawFunction(biEciesX25519PublicKeyFromPrivateKey_wrapper) {
  m3ApiReturnType(biOpaqueEciesX25519PublicKey);
  m3ApiGetArg(biOpaqueP256PrivateKey, privkey);
  biOpaqueEciesX25519PublicKey pubkey =
      biEciesX25519PublicKeyFromPrivateKey(privkey);
  m3ApiReturn(pubkey);
}

biOpaqueEciesX25519PublicKey biEciesX25519PublicKeyFromPrivateKey(
    biOpaqueEciesX25519PrivateKey privkey) {
  InitGlobalsIfNeeded();
  ByteString pubkey = *ecies_x25519_privkey_slab->Get(privkey)->GetPublicKey();
  return ecies_x25519_pubkey_slab->Create(new EciesX25519PublicKey(pubkey))
      .Serialize();
}

m3ApiRawFunction(biEciesX25519PublicKeyFromBin_wrapper) {
  m3ApiReturnType(biOpaqueEciesX25519PublicKey);
  m3ApiGetArgMem(const void*, bytes);
  SC_CHECK(MemCheckRange(bytes, X25519_PUBLIC_VALUE_LEN));
  biOpaqueEciesX25519PublicKey pubkey = biEciesX25519PublicKeyFromBin(bytes);
  m3ApiReturn(pubkey);
}

biOpaqueEciesX25519PublicKey biEciesX25519PublicKeyFromBin(const void* bytes) {
  InitGlobalsIfNeeded();
  return ecies_x25519_pubkey_slab
      ->Create(
          new EciesX25519PublicKey(ByteString(bytes, X25519_PUBLIC_VALUE_LEN)))
      .Serialize();
}

m3ApiRawFunction(biDestroyEciesX25519PrivateKey_wrapper) {
  m3ApiGetArg(biOpaqueEciesX25519PrivateKey, privkey);
  biDestroyEciesX25519PrivateKey(privkey);
  m3ApiSuccess();
}

void biDestroyEciesX25519PrivateKey(biOpaqueEciesX25519PrivateKey privkey) {
  InitGlobalsIfNeeded();
  ecies_x25519_privkey_slab->Destroy(privkey);
}

m3ApiRawFunction(biDestroyEciesX25519PublicKey_wrapper) {
  m3ApiGetArg(biOpaqueEciesX25519PublicKey, pubkey);
  biDestroyEciesX25519PublicKey(pubkey);
  m3ApiSuccess();
}

void biDestroyEciesX25519PublicKey(biOpaqueEciesX25519PublicKey pubkey) {
  InitGlobalsIfNeeded();
  ecies_x25519_pubkey_slab->Destroy(pubkey);
}

m3ApiRawFunction(biEciesX25519AesGcmHkdfEncrypt_wrapper) {
  m3ApiGetArg(biOpaqueEciesX25519PublicKey, pubkey);
  m3ApiGetArgMem(const void*, in);
  m3ApiGetArg(int32_t, in_len);
  m3ApiGetArgMem(const void*, context_info);
  m3ApiGetArg(int32_t, context_info_len);
  m3ApiGetArgMem(void*, out);
  SC_CHECK(MemCheckRange(in, in_len));
  SC_CHECK(MemCheckRange(context_info, context_info_len));
  size_t out_len = X25519_PUBLIC_VALUE_LEN + uefi_crypto::kAesGcmNonceLength +
                   in_len + uefi_crypto::kAesGcmTagLength;
  SC_CHECK(MemCheckRange(out, out_len));
  biEciesX25519AesGcmHkdfEncrypt(pubkey, in, in_len, context_info,
                                 context_info_len, out);
  m3ApiSuccess();
}

void biEciesX25519AesGcmHkdfEncrypt(biOpaqueEciesX25519PublicKey pubkey,
                                    const void* in, int32_t in_len,
                                    const void* context_info,
                                    int32_t context_info_len, void* out) {
  const auto* pubkey_ptr = ecies_x25519_pubkey_slab->Get(pubkey);
  auto ciphertext = pubkey_ptr->Encrypt(
      SecretByteString(in, in_len),
      std::string(reinterpret_cast<const char*>(context_info),
                  context_info_len));
  memcpy(out, ciphertext.data(), ciphertext.size());
}

m3ApiRawFunction(biEciesX25519AesGcmHkdfDecrypt_wrapper) {
  m3ApiReturnType(biBool);
  m3ApiGetArg(biOpaqueEciesX25519PrivateKey, privkey);
  m3ApiGetArgMem(const void*, in);
  m3ApiGetArg(int32_t, in_len);
  m3ApiGetArgMem(const void*, context_info);
  m3ApiGetArg(int32_t, context_info_len);
  m3ApiGetArgMem(void*, out);
  SC_CHECK(MemCheckRange(in, in_len));
  SC_CHECK(MemCheckRange(context_info, context_info_len));
  size_t out_len = in_len - X25519_PUBLIC_VALUE_LEN -
                   uefi_crypto::kAesGcmNonceLength -
                   uefi_crypto::kAesGcmTagLength;
  SC_CHECK(MemCheckRange(out, out_len));
  auto success = biEciesX25519AesGcmHkdfDecrypt(
      privkey, in, in_len, context_info, context_info_len, out);
  m3ApiReturn(success);
}

biBool biEciesX25519AesGcmHkdfDecrypt(biOpaqueEciesX25519PrivateKey privkey,
                                      const void* in, int32_t in_len,
                                      const void* context_info,
                                      int32_t context_info_len, void* out) {
  const auto* privkey_ptr = ecies_x25519_privkey_slab->Get(privkey);
  auto status_or_plaintext = privkey_ptr->Decrypt(
      std::string(reinterpret_cast<const char*>(in), in_len),
      std::string(reinterpret_cast<const char*>(context_info),
                  context_info_len));
  if (!status_or_plaintext) return false;
  memcpy(out, status_or_plaintext->data(), status_or_plaintext->size());
  return true;
}

m3ApiRawFunction(biEciesP256PublicKeyFromBin_wrapper) {
  m3ApiReturnType(biOpaqueEciesP256PublicKey);
  m3ApiGetArgMem(const void*, bytes);
  SC_CHECK(MemCheckRange(bytes, P256_NBYTES_COMPRESSED));
  biOpaqueEciesP256PublicKey pubkey = biEciesP256PublicKeyFromBin(bytes);
  m3ApiReturn(pubkey);
}

biOpaqueEciesP256PublicKey biEciesP256PublicKeyFromBin(const void* bytes) {
  InitGlobalsIfNeeded();
  auto status_or_pubkey =
      EciesP256PublicKey::Create(ByteString(bytes, P256_NBYTES_COMPRESSED));
  // TODO(b/242577301): This should not crash the sealing policy.
  SC_CHECK(status_or_pubkey.ok());
  return ecies_p256_pubkey_slab->Create(status_or_pubkey->release())
      .Serialize();
}

m3ApiRawFunction(biDestroyEciesP256PublicKey_wrapper) {
  m3ApiGetArg(biOpaqueEciesP256PublicKey, pubkey);
  biDestroyEciesP256PublicKey(pubkey);
  m3ApiSuccess();
}

void biDestroyEciesP256PublicKey(biOpaqueEciesP256PublicKey pubkey) {
  InitGlobalsIfNeeded();
  ecies_p256_pubkey_slab->Destroy(pubkey);
}

m3ApiRawFunction(biEciesP256AesGcmHkdfEncrypt_wrapper) {
  m3ApiGetArg(biOpaqueEciesP256PublicKey, pubkey);
  m3ApiGetArgMem(const void*, in);
  m3ApiGetArg(int32_t, in_len);
  m3ApiGetArgMem(const void*, context_info);
  m3ApiGetArg(int32_t, context_info_len);
  m3ApiGetArgMem(void*, out);
  SC_CHECK(MemCheckRange(in, in_len));
  SC_CHECK(MemCheckRange(context_info, context_info_len));
  constexpr size_t padding = P256_NBYTES_COMPRESSED +
                             uefi_crypto::kAesGcmNonceLength +
                             uefi_crypto::kAesGcmTagLength;
  size_t out_len = in_len + padding;
  SC_CHECK(MemCheckRange(out, out_len));
  biEciesP256AesGcmHkdfEncrypt(pubkey, in, in_len, context_info,
                               context_info_len, out);
  m3ApiSuccess();
}

void biEciesP256AesGcmHkdfEncrypt(biOpaqueEciesP256PublicKey pubkey,
                                  const void* in, int32_t in_len,
                                  const void* context_info,
                                  int32_t context_info_len, void* out) {
  const auto* pubkey_ptr = ecies_p256_pubkey_slab->Get(pubkey);
  auto ciphertext = pubkey_ptr->Encrypt(
      SecretByteString(in, in_len),
      std::string(reinterpret_cast<const char*>(context_info),
                  context_info_len));
  memcpy(out, ciphertext.data(), ciphertext.size());
}

}  // extern "C"

namespace {

// Note that globals are not destroyed at program termination.
void InitGlobals() {
  sha_slab = new Sha256Slab();
  hmac_slab = new HmacSha256Slab();
  bignum_slab = new BignumSlab();
  ec_point_slab = new EcPointSlab();
  private_key_slab = new P256PrivateKeySlab();
  public_key_slab = new P256PublicKeySlab();
  ecdsa_sig_slab = new EcdsaSigSlab();
  aes_slab = new AesSlab();
  aes_gcm_slab = new AesGcmSlab();
  ecies_x25519_privkey_slab = new EciesX25519PrivateKeySlab();
  ecies_x25519_pubkey_slab = new EciesX25519PublicKeySlab();
  ecies_p256_pubkey_slab = new EciesP256PublicKeySlab();
  global_cprng = new Cprng();
  if (sha_slab == nullptr || hmac_slab == nullptr || bignum_slab == nullptr ||
      ec_point_slab == nullptr || private_key_slab == nullptr ||
      public_key_slab == nullptr || ecdsa_sig_slab == nullptr ||
      aes_slab == nullptr || aes_gcm_slab == nullptr ||
      ecies_x25519_privkey_slab == nullptr ||
      ecies_x25519_pubkey_slab == nullptr ||
      ecies_p256_pubkey_slab == nullptr || global_cprng == nullptr) {
    SC_LOG(FATAL) << "Out of memory";
  }
  SeedGlobalCprng();
  globals_initialized = true;
}

}  // namespace

}  // namespace enforcer
}  // namespace wasm
}  // namespace sealed
