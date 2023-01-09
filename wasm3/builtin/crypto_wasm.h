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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_BUILTIN_CRYPTO_WASM_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_BUILTIN_CRYPTO_WASM_H_

// Crypto API to interface with the WASM VM.

#include "third_party/sealedcomputing/wasm3/builtin/wasm_types.h"

#ifdef __cplusplus
#include <cstdint>
extern "C" {
#else
#include <stdint.h>
#endif

biOpaqueBignum biBignumFromBin(const biBignum src);
void biBignumToBin(biOpaqueBignum bignum, biBignum dst);
void biDestroyBignum(biOpaqueBignum bignum);
biOpaqueBignum biBignumOne(void);

biOpaqueP256Point biP256PointFromBin(const biP256Point src);
void biP256PointToBin(biOpaqueP256Point ec_point, biP256Point dst);
void biDestroyPoint(biOpaqueP256Point ec_point);

biOpaqueP256PrivateKey biP256PrivateKeyFromBin(const biBignum src);
void biP256PrivateKeyToBin(biOpaqueP256PrivateKey key, biBignum dst);
void biDestroyP256PrivateKey(biOpaqueP256PrivateKey src);

biOpaqueP256PublicKey biP256PublicKeyFromBin(const biP256Point src);
biOpaqueP256PublicKey biP256PublicKeyFromPrivateKey(biOpaqueP256PrivateKey key);
void biP256PublicKeyToBin(biOpaqueP256PublicKey key, biP256Point dst);
void biDestroyP256PublicKey(biOpaqueP256PublicKey src);

biOpaqueEcdsaSig biEcdsaSigFromBin(const biEcdsaSig src);
void biEcdsaSigToBin(biOpaqueEcdsaSig sig, biEcdsaSig dst);
void biDestroyEcdsaSig(biOpaqueEcdsaSig src);

biOpaqueAesKey biAesKeyFromBin(const biAesKey src);
void biDestroyAesKey(biOpaqueAesKey key);

biOpaqueAesGcmKey biAesGcmKeyFromBin(const biAesGcmKey src);
void biDestroyAesGcmKey(biOpaqueAesGcmKey key);

biOpaqueP256PrivateKey biGenP256PrivateKey(void);

biOpaqueP256Point biP256BasePointMul(biOpaqueBignum n);

biOpaqueP256Point biP256PointMul(biOpaqueBignum n, biOpaqueP256Point ec_point);

biOpaqueEcdsaSig biP256EcdsaSign(biOpaqueP256PrivateKey key, const void* digest,
                                 int32_t digest_len);

biBool biP256EcdsaVerify(biOpaqueP256PublicKey key, const void* digest,
                         int32_t digest_len, biOpaqueEcdsaSig sig);

biBool biP256IsValidPoint(biOpaqueP256Point ec_point);

void biEncryptAesBlock(biOpaqueAesKey aes_key, const biAesBlock in,
                       biAesBlock out);

void biDecryptAesBlock(biOpaqueAesKey aes_key, const biAesBlock in,
                       biAesBlock out);

void biAesGcmEncrypt(biOpaqueAesGcmKey key, const void* nonce, const void* in,
                     int32_t in_len, const void* ad, int32_t ad_len, void* out,
                     void* out_len);

void biAesGcmDecrypt(biOpaqueAesGcmKey key, const void* nonce, const void* in,
                     int32_t in_len, const void* ad, int32_t ad_len, void* out,
                     void* out_len);

void biSha256(const void* data, biSizeT data_len, biSha256Digest digest);
biOpaqueSha256 biSha256init();
void biSha256update(biOpaqueSha256 opaque_sha, const void* data,
                    int32_t data_len);
void biSha256final(biOpaqueSha256 opaque_sha, biSha256Digest digest);

void biHmacSha256(const void* key, biSizeT key_len, const void* data,
                  biSizeT data_len, biSha256Digest digest);
biOpaqueHmac biHmacSha256init(const void* key, biSizeT key_len);
void biHmacSha256update(biOpaqueHmac opaque_hmac, const void* data,
                        biSizeT data_len);
void biHmacSha256final(biOpaqueHmac opaque_hmac, biSha256Digest digest);

void biHkdf(int32_t out_len, const void* secret, int32_t secret_len,
            const void* salt, int32_t salt_len, const void* info,
            int32_t info_len, void* out_key);

void biRandBytes(void* buf, int32_t len);

biOpaqueEciesX25519PrivateKey biGenEciesX25519PrivateKey();
biOpaqueEciesX25519PublicKey biEciesX25519PublicKeyFromPrivateKey(
    biOpaqueEciesX25519PrivateKey privkey);
biOpaqueEciesX25519PublicKey biEciesX25519PublicKeyFromBin(const void* bytes);
void biDestroyEciesX25519PrivateKey(biOpaqueEciesX25519PrivateKey privkey);
void biDestroyEciesX25519PublicKey(biOpaqueEciesX25519PublicKey pubkey);

void biEciesX25519AesGcmHkdfEncrypt(biOpaqueEciesX25519PublicKey pubkey,
                                    const void* in, int32_t in_len,
                                    const void* context_info,
                                    int32_t context_info_len, void* out);
biBool biEciesX25519AesGcmHkdfDecrypt(biOpaqueEciesX25519PrivateKey privkey,
                                      const void* in, int32_t in_len,
                                      const void* context_info,
                                      int32_t context_info_len, void* out);

biOpaqueEciesP256PublicKey biEciesP256PublicKeyFromBin(const void* bytes);
void biDestroyEciesP256PublicKey(biOpaqueEciesP256PublicKey pubkey);

void biEciesP256AesGcmHkdfEncrypt(biOpaqueEciesP256PublicKey pubkey,
                                  const void* in, int32_t in_len,
                                  const void* context_info,
                                  int32_t context_info_len, void* out);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_BUILTIN_CRYPTO_WASM_H_
