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

#include <cstdint>

#include "third_party/sealedcomputing/wasm3/builtin/crypto_wasm.h"
#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/crypto.h"
#include "third_party/sealedcomputing/wasm3/logging.h"

using ::sealed::wasm::ByteString;

extern "C" int start() {
  biOpaqueP256PrivateKey priv_key_ptr = biGenP256PrivateKey();
  ByteString pub_key(65);
  {
    biOpaqueP256PublicKey pub_key_ptr =
        biP256PublicKeyFromPrivateKey(priv_key_ptr);
    biP256PublicKeyToBin(pub_key_ptr, pub_key.data());
    biDestroyP256PublicKey(pub_key_ptr);
  }

  ByteString digest = sealed::wasm::Sha256::Digest("data");

  ByteString sig(64);
  {
    biOpaqueEcdsaSig sig_ptr =
        biP256EcdsaSign(priv_key_ptr, digest.data(), digest.size());
    biEcdsaSigToBin(sig_ptr, sig.data());
    biDestroyEcdsaSig(sig_ptr);
  }

  biOpaqueP256PublicKey pub_key_ptr = biP256PublicKeyFromBin(pub_key.data());
  biOpaqueEcdsaSig sig_ptr = biEcdsaSigFromBin(sig.data());
  int32_t result =
      biP256EcdsaVerify(pub_key_ptr, digest.data(), digest.size(), sig_ptr);

  biDestroyEcdsaSig(sig_ptr);
  biDestroyP256PublicKey(pub_key_ptr);
  biDestroyP256PrivateKey(priv_key_ptr);

  return 1 - result;
}
