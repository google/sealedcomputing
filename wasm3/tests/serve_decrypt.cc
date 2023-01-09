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

#include <algorithm>

#include "third_party/sealedcomputing/wasm3/base.h"
#include "third_party/sealedcomputing/wasm3/builtin/builtin_wasm.h"
#include "third_party/sealedcomputing/wasm3/builtin/crypto_wasm.h"
#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/logging.h"
#include "third_party/sealedcomputing/wasm3/statusor.h"
#include "third_party/sealedcomputing/wasm3/tests/serve_decrypt.common.h"

WASM_EXPORT int start() {
  sealed::wasm::tests::server::RegisterRpcHandlers();
  sealed::wasm::Serve();
  return 0;
}

namespace sealed {
namespace wasm {
namespace tests {
namespace server {

using ::sealed::wasm::ByteString;
using ::sealed::wasm::DecryptWithGroupKey;
using ::sealed::wasm::SecretByteString;
using ::sealed::wasm::StatusOr;

constexpr uint8_t context_info[] = "context_info";

StatusOr<DecryptResponse> Decrypt(const DecryptRequest& request) {
  StatusOr<SecretByteString> plaintext =
      DecryptWithGroupKey(request.ciphertext, "");
  SC_CHECK(plaintext.ok());
  return DecryptResponse{plaintext->string()};
}

StatusOr<DecryptResponse> DecryptP256(const DecryptRequest& request) {
  SecretByteString plaintext(request.ciphertext.size() - 61);
  SC_CHECK(biGroupEciesP256AesGcmHkdfDecrypt(
      request.ciphertext.data(), request.ciphertext.size(), context_info,
      sizeof(context_info), plaintext.data()));
  return DecryptResponse{plaintext.string()};
}

StatusOr<EncryptResponse> Encrypt(const EncryptRequest& request) {
  return EncryptResponse{
      wasm::EncryptWithGroupKey(request.plaintext, "").string()};
}

StatusOr<EncryptResponse> EncryptP256(const EncryptRequest& request) {
  // Get a handle for the job P256 public key.
  uint8_t pubkey[33];
  biGroupEciesP256PublicKeyToBin(pubkey);
  auto pubkey_handle = biEciesP256PublicKeyFromBin(pubkey);

  // Encrypt to the job P256 public key.
  ByteString ciphertext(request.plaintext.size() + 61);
  biEciesP256AesGcmHkdfEncrypt(pubkey_handle, request.plaintext.data(),
                               request.plaintext.size(), context_info,
                               sizeof(context_info), ciphertext.data());
  return EncryptResponse{ciphertext.string()};
}

StatusOr<PanicResponse> Panic(const PanicRequest& request) {
  SC_PANIC() << "This error is expected.";
  return PanicResponse();
}

}  // namespace server
}  // namespace tests
}  // namespace wasm
}  // namespace sealed
