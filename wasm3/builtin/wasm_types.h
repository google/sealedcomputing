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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_BUILTIN_WASM_TYPES_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_BUILTIN_WASM_TYPES_H_

// bool
#define biBool int32_t

// size_t
#define biSizeT int32_t

// uint8_t[P256_SCALAR_NBYTES]
#define biBignum void*

// uint8_t[P256_NBYTES]
#define biP256Point void*

// uint8_t[ECDSA_NBYTES]
#define biEcdsaSig void*

// uint8_t[AES_128_KEY_SIZE]
#define biAesKey void*

// uint8_t[AES_BLOCK_SIZE]
#define biAesBlock void*

// uint8_t[AES_128_KEY_LEN]
#define biAesGcmKey void*

// uint8_t[AES_GCM_NONCE_LEN]
#define biAesGcmNonce void*

// uint8_t[SHA256_DIGEST_LENGTH]
#define biSha256Digest void*

#define biOpaqueBignum int64_t
#define biOpaqueP256Point int64_t
#define biOpaqueP256PublicKey int64_t
#define biOpaqueP256PrivateKey int64_t
#define biOpaqueEcdsaSig int64_t
#define biOpaqueAesCtx int64_t
#define biOpaqueAesKey int64_t
#define biOpaqueAesGcmKey int64_t
#define biOpaqueSha256 int64_t
#define biOpaqueHmac int64_t
#define biOpaqueEciesX25519PrivateKey int64_t
#define biOpaqueEciesX25519PublicKey int64_t
#define biOpaqueEciesP256PublicKey int64_t

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_BUILTIN_WASM_TYPES_H_
