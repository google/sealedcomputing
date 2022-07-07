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

// Test our custom HMAC implementation.  This test compiles both to Linux, and
// also to Nanolibc for testing in the UEFI enclave.

#include "third_party/sealedcomputing/wasm3/enforcer/uefi_crypto/hkdf_sha256.h"

#include <cstdint>
#include <cstdio>
#include <cstring>

#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/enforcer/uefi_crypto/test_fakes.h"
#include "third_party/sealedcomputing/wasm3/logging.h"

namespace sealed {
namespace wasm {
namespace uefi_crypto {
namespace {

// Test that HKDF-SHA256 computes the known good result.
void HkdfSha256Test(ByteString secret, ByteString salt, ByteString info,
                    ByteString expected_result) {
  SecretByteString out = HkdfSha256(expected_result.size(), secret, salt, info);
  SC_CHECK(out == expected_result);
}

}  // namespace
}  // namespace uefi_crypto
}  // namespace wasm
}  // namespace sealed

int main() {
  // These vectors were generated with the online HKDF calculator at
  // https://asecuritysite.com/encryption/HKDF.
  sealed::wasm::uefi_crypto::HkdfSha256Test(
      "secret", "salt", "info",
      sealed::wasm::ByteString(
          "\xf6\xd2\xfc\xc4\x7c\xb9\x39\xde\xaf\xe3\x85\x3a\x1e\x64\x1a\x27",
          16));
  sealed::wasm::uefi_crypto::HkdfSha256Test(
      "secret", "", "info",
      sealed::wasm::ByteString(
          "\x7e\x11\xa1\x91\xfa\x87\x99\x19\xdc\xf4\xe3\x36\xe0\xd7\x36\x09",
          16));
  sealed::wasm::uefi_crypto::HkdfSha256Test(
      sealed::wasm::ByteString("Now is the time for all good men to come to "
                               "the aid of their country."),
      sealed::wasm::ByteString(35, '\xaa'),
      sealed::wasm::ByteString(40, '\xbb'),
      sealed::wasm::ByteString(
          "\x3a\xfe\xc8\x51\x8e\x77\x3c\x08\x95\x8b\xc2\x30\xe6\x3a\xf9\x73\xf5"
          "\x3b\xa1\x10\x2d\x55\x2b\x9d\xc9\x52\x37\x11\x80\x9e\x77\xc6\xd7\xb2"
          "\xb3\x05\x85\x39\x57\x95\x46\x94\x49\x83\xbe\xac\xac\xc0\x93\x50\x9b"
          "\xdd\x62\x64\xe2\xcc\xeb\x45\xc1\x4a\x53\xeb\xad\xfb",
          64));
  SC_LOG(INFO) << "PASSED";
  return 0;
}
