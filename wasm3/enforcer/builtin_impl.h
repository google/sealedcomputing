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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_BUILTIN_IMPL_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_BUILTIN_IMPL_H_

#include <cstdint>
#include <vector>

#include "third_party/wasm3/source/wasm3.h"

extern "C" {

m3ApiRawFunction(biPrintln_wrapper);
m3ApiRawFunction(biSign_wrapper);
m3ApiRawFunction(biVerify_wrapper);
m3ApiRawFunction(biPanic_wrapper);
m3ApiRawFunction(biSendRpc_wrapper);
m3ApiRawFunction(biSendTransactionalRpc_wrapper);
m3ApiRawFunction(biSendLogRpc_wrapper);
m3ApiRawFunction(biRegisterRpcHandler_wrapper);
m3ApiRawFunction(biServe_wrapper);
m3ApiRawFunction(biAesKeyFromBin_wrapper);
m3ApiRawFunction(biAesGcmKeyFromBin_wrapper);
m3ApiRawFunction(biEncryptAesBlock_wrapper);
m3ApiRawFunction(biDecryptAesBlock_wrapper);
m3ApiRawFunction(biAesGcmEncrypt_wrapper);
m3ApiRawFunction(biAesGcmDecrypt_wrapper);
m3ApiRawFunction(biDestroyAesGcmKey_wrapper);
m3ApiRawFunction(biSha256_wrapper);
m3ApiRawFunction(biSha256init_wrapper);
m3ApiRawFunction(biSha256update_wrapper);
m3ApiRawFunction(biSha256final_wrapper);
m3ApiRawFunction(biHmacSha256_wrapper);
m3ApiRawFunction(biHmacSha256init_wrapper);
m3ApiRawFunction(biHmacSha256update_wrapper);
m3ApiRawFunction(biHmacSha256final_wrapper);
m3ApiRawFunction(biHkdf_wrapper);
m3ApiRawFunction(biGetRequest_wrapper);
m3ApiRawFunction(biGetRequestSecret_wrapper);
m3ApiRawFunction(biGetRequestSecretLength_wrapper);
m3ApiRawFunction(biSetResponse_wrapper);
m3ApiRawFunction(biSetResponseSecret_wrapper);
m3ApiRawFunction(biSetResponseStatus_wrapper);
m3ApiRawFunction(biGetSendRpcResponse_wrapper);
m3ApiRawFunction(biGetSendRpcResponseSecret_wrapper);
m3ApiRawFunction(biGetSendRpcStatusMessage_wrapper);
m3ApiRawFunction(biDecryptWithGroupKey_wrapper);
m3ApiRawFunction(biDecryptWithGroupKeyFinish_wrapper);
m3ApiRawFunction(biEncryptWithGroupKey_wrapper);
m3ApiRawFunction(biEncryptWithGroupKeyFinish_wrapper);
m3ApiRawFunction(biRandBytes_wrapper);
m3ApiRawFunction(biGenP256PrivateKey_wrapper);
m3ApiRawFunction(biP256PublicKeyFromPrivateKey_wrapper);
m3ApiRawFunction(biP256PrivateKeyFromBin_wrapper);
m3ApiRawFunction(biP256PrivateKeyToBin_wrapper);
m3ApiRawFunction(biP256EcdsaSign_wrapper);
m3ApiRawFunction(biEcdsaSigToBin_wrapper);
m3ApiRawFunction(biP256PublicKeyToBin_wrapper);
m3ApiRawFunction(biDestroyP256PublicKey_wrapper);
m3ApiRawFunction(biDestroyEcdsaSig_wrapper);
m3ApiRawFunction(biDestroyP256PrivateKey_wrapper);
m3ApiRawFunction(biP256PublicKeyFromBin_wrapper);
m3ApiRawFunction(biEcdsaSigFromBin_wrapper);
m3ApiRawFunction(biP256EcdsaVerify_wrapper);
m3ApiRawFunction(biGenEciesX25519PrivateKey_wrapper);
m3ApiRawFunction(biEciesX25519PublicKeyFromPrivateKey_wrapper);
m3ApiRawFunction(biEciesX25519PublicKeyFromBin_wrapper);
m3ApiRawFunction(biDestroyEciesX25519PrivateKey_wrapper);
m3ApiRawFunction(biDestroyEciesX25519PublicKey_wrapper);
m3ApiRawFunction(biEciesX25519AesGcmHkdfEncrypt_wrapper);
m3ApiRawFunction(biEciesX25519AesGcmHkdfDecrypt_wrapper);
m3ApiRawFunction(biGroupEciesP256PublicKeyToBin_wrapper);
m3ApiRawFunction(biEciesP256PublicKeyFromBin_wrapper);
m3ApiRawFunction(biDestroyEciesP256PublicKey_wrapper);
m3ApiRawFunction(biEciesP256AesGcmHkdfEncrypt_wrapper);
m3ApiRawFunction(biGroupEciesP256AesGcmHkdfDecrypt_wrapper);

}  // extern "C"

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_BUILTIN_IMPL_H_
