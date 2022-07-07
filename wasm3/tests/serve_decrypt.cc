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
#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/logging.h"
#include "third_party/sealedcomputing/wasm3/statusor.h"
#include "third_party/sealedcomputing/wasm3/tests/serve_decrypt.common.h"

WASM_EXPORT int start() {
  sealed::wasm::tests::server::RegisterRpcHandlers();
  sealed::wasm::Serve();
  return 0;
}

namespace sealed::wasm::tests::server {

using ::sealed::wasm::DecryptWithGroupKey;
using ::sealed::wasm::SecretByteString;
using ::sealed::wasm::StatusOr;

StatusOr<DecryptResponse> Decrypt(const DecryptRequest& request) {
  StatusOr<SecretByteString> plaintext =
      DecryptWithGroupKey(request.ciphertext, "");
  SC_CHECK(plaintext.ok());
  return DecryptResponse{plaintext->string()};
}

StatusOr<EncryptResponse> Encrypt(const EncryptRequest& request) {
  return EncryptResponse{
      wasm::EncryptWithGroupKey(request.plaintext, "").string()};
}

StatusOr<PanicResponse> Panic(const PanicRequest& request) {
  SC_PANIC() << "This error is expected.";
  return PanicResponse{};
}

}  // namespace sealed::wasm::tests::server
