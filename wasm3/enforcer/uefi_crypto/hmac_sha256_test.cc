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

// Test our custom HMAC-SHA256 implementation.  This test compiles both to
// Linux, and also to Nanolibc for testing in the UEFI enclave.

#include "third_party/sealedcomputing/wasm3/enforcer/uefi_crypto/hmac_sha256.h"

#include <cstdint>
#include <cstdio>
#include <cstring>

#include "third_party/sealedcomputing/wasm3/base.h"
#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/enforcer/uefi_crypto/test_fakes.h"
#include "third_party/sealedcomputing/wasm3/logging.h"

namespace sealed {
namespace wasm {
namespace uefi_crypto {
namespace {

// Test that our HMAC-SHA256 implementation gets the right answer for a given
// known good vector.
void HmacSha256Test(const SecretByteString& key, const ByteString& first_part,
                    const ByteString& last_part,
                    const ByteString& expected_result) {
  SC_LOG(INFO) << "Starting HmacSha256Test";
  HmacSha256Ctx ctx;
  HmacSha256Init(&ctx, key);
  SC_LOG(INFO) << "Calling HmacSha256Update";
  HmacSha256Update(&ctx, first_part);
  SC_LOG(INFO) << "Calling HmacSha256Update";
  HmacSha256Update(&ctx, last_part);
  SC_LOG(INFO) << ("Calling HmacSha256Final");
  SecretByteString result = HmacSha256Final(&ctx);
  SC_LOG(INFO) << result.hex();
  SC_CHECK(result == expected_result);
  SC_LOG(INFO) << "Passed NamcTest";
  // Now check we get the same result with Hmac.
  ByteString data = first_part + last_part;
  result = HmacSha256(key, data);
  SC_CHECK(result == expected_result);
}

}  // namespace
}  // namespace uefi_crypto
}  // namespace wasm
}  // namespace sealed

int main() {
  sealed::wasm::uefi_crypto::HmacSha256Test(
      sealed::wasm::ByteString(32, 'a'), "Hello, ", "World!",
      "\xc5\xb4\x79\xfd\x60\xed\x13\xa1\xec\x48\x79\x05\x0b\x19\xae\xb9\x88\x54"
      "\x0a\x9a\xe9\xaf\xfa\x86\xd8\xa2\xdb\x1f\x3e\x77\x82\x36");
  sealed::wasm::uefi_crypto::HmacSha256Test(
      sealed::wasm::ByteString(33, 'z'), "Now is the time for all good men to ",
      "come to the aid of their country.",
      "\x27\x3d\x99\x6c\x04\x20\x07\x49\xc5\x81\x80\xa1\x4c\xdc\xf6\x99\xea\xdc"
      "\x2e\x46\xdf\x01\x20\x40\x88\x80\x9e\x71\x07\xa3\x56\x2e");
  sealed::wasm::uefi_crypto::HmacSha256Test(
      sealed::wasm::ByteString(65, 'm'), "Now is the time for all good men to ",
      "come to the aid of their country.",
      "\x86\xe0\x38\x60\xf3\xe0\x47\xda\x8f\xa6\x63\x24\x04\x18\x50\xe8\xd6\x81"
      "\xce\xca\x21\xda\x50\xae\x34\xd1\xc8\xb1\x51\xd6\x1d\xcf");
  SC_LOG(INFO) << "PASSED";
  return 0;
}
