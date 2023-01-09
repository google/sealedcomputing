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

  // Test vectors from https://datatracker.ietf.org/doc/html/rfc5869
  // A.1.  Test Case 1
  sealed::wasm::ByteString ikm = *sealed::wasm::ByteString::Hex(
      "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
  sealed::wasm::ByteString salt =
      *sealed::wasm::ByteString::Hex("000102030405060708090a0b0c");
  sealed::wasm::ByteString info =
      *sealed::wasm::ByteString::Hex("f0f1f2f3f4f5f6f7f8f9");
  sealed::wasm::ByteString expected_result = *sealed::wasm::ByteString::Hex(
      "3cb25f25faacd57a90434f64d0362f2a"
      "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
      "34007208d5b887185865");
  sealed::wasm::uefi_crypto::HkdfSha256Test(ikm, salt, info, expected_result);

  // A.3.  Test Case 3
  expected_result = *sealed::wasm::ByteString::Hex(
      "8da4e775a563c18f715f802a063c5a31"
      "b8a11f5c5ee1879ec3454e5f3c738d2d"
      "9d201395faa4b61a96c8");
  sealed::wasm::uefi_crypto::HkdfSha256Test(ikm, "", "", expected_result);

  // A.2.  Test Case 2
  ikm = *sealed::wasm::ByteString::Hex(
      "000102030405060708090a0b0c0d0e0f"
      "101112131415161718191a1b1c1d1e1f"
      "202122232425262728292a2b2c2d2e2f"
      "303132333435363738393a3b3c3d3e3f"
      "404142434445464748494a4b4c4d4e4f");
  salt = *sealed::wasm::ByteString::Hex(
      "606162636465666768696a6b6c6d6e6f"
      "707172737475767778797a7b7c7d7e7f"
      "808182838485868788898a8b8c8d8e8f"
      "909192939495969798999a9b9c9d9e9f"
      "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
  info = *sealed::wasm::ByteString::Hex(
      "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
      "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
      "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
      "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
      "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
  expected_result = *sealed::wasm::ByteString::Hex(
      "b11e398dc80327a1c8e7f78c596a4934"
      "4f012eda2d4efad8a050cc4c19afa97c"
      "59045a99cac7827271cb41c65e590e09"
      "da3275600c2f09b8367793a9aca3db71"
      "cc30c58179ec3e87c14c01d5c1f3434f"
      "1d87");
  sealed::wasm::uefi_crypto::HkdfSha256Test(ikm, salt, info, expected_result);

  SC_LOG(INFO) << "PASSED";
  return 0;
}
