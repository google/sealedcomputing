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

#include "third_party/sealedcomputing/wasm3/enforcer/uefi_crypto/hkdf_sha256.h"

#include <string.h>

#include "third_party/sealedcomputing/wasm3/enforcer/uefi_crypto/hmac_sha256.h"
#include "third_party/sealedcomputing/wasm3/enforcer/uefi_crypto/init_crypto.h"

namespace sealed {
namespace wasm {
namespace uefi_crypto {

// See https://datatracker.ietf.org/doc/html/rfc5869 for a description.
SecretByteString HkdfSha256(size_t out_len, const SecretByteString& secret,
                            const ByteString& salt, const ByteString& info) {
  if (!global_initialized) {
    InitializeCryptoLib();
  }
  const ByteString s = salt.empty() ? ByteString(32, '\0') : salt;
  const SecretByteString prk = HmacSha256(s, secret);
  SecretByteString T;
  SecretByteString result(out_len);
  uint8_t* out = result.data();
  size_t out_pos = 0;
  size_t num_to_copy;
  for (uint8_t i = 1; out_pos < out_len; ++i) {
    T = HmacSha256(prk, T + info + ByteString(1, i));
    num_to_copy = out_pos + T.size() <= out_len ? T.size() : out_len - out_pos;
    memcpy(out + out_pos, T.data(), num_to_copy);
    out_pos += num_to_copy;
  }
  return result;
}

}  // namespace uefi_crypto
}  // namespace wasm
}  // namespace sealed
