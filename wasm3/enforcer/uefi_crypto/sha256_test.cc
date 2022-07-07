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

// Test SHA256_NI implementation test.  This test compiles both to Linux, and
// also to Nanolibc for testing in the UEFI enclave.

#include "third_party/sealedcomputing/wasm3/enforcer/uefi_crypto/sha256.h"

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

// Test that the hash of "Hello, World!" is right.
void Sha256HelloTest() {
  SC_LOG(INFO) << "Starting Sha256HelloTest";
  ByteString hello = "Hello, ";
  ByteString world = "World!";
  Sha256Ctx ctx;
  Sha256Init(&ctx);
  SC_LOG(INFO) << "Calling SHA256_Update";
  Sha256Update(&ctx, hello);
  SC_LOG(INFO) << "Calling SHA256_Update";
  Sha256Update(&ctx, world);
  SC_LOG(INFO) << ("Calling SHA256_Final");
  SecretByteString digest = Sha256Final(&ctx);
  SC_LOG(INFO) << digest.hex();
  ByteString expected_result =
      "\xdf\xfd\x60\x21\xbb\x2b\xd5\xb0\xaf\x67\x62\x90\x80\x9e\xc3\xa5\x31\x91"
      "\xdd\x81\xc7\xf7\x0a\x4b\x28\x68\x8a\x36\x21\x82\x98\x6f";
  SC_CHECK(digest == expected_result);
  SC_LOG(INFO) << "Passed Sha256HelloTest";
}

// Do one node's worth of Merkle hashing.
inline void MerkleHash(const SecretByteString& left,
                       const SecretByteString& right, SecretByteString* out) {
  Sha256Ctx ctx;
  Sha256Init(&ctx);
  Sha256Update(&ctx, left);
  Sha256Update(&ctx, right);
  Sha256Final(&ctx, out);
}

// Test 10,000,000 Merkle hashes.  This should be enough for the INFO log time
// data to give us an accurate speed measurement.
void Sha256MerkleSpeedTest() {
  SC_LOG(INFO) << "Starting Sha256MerkleSpeedTest";
  uint8_t data[kSha256DigestLength] = {0x00, 0x01, 0x02, 0x03,
                                       0x04, 0x05, 0x06, 0x07};
  SecretByteString hash(data, sizeof(data));
  SecretByteString out = hash;
  for (uint32_t i = 0; i < 10000000; i++) {
    MerkleHash(hash, out, &out);
  }
  SC_LOG(INFO) << out.hex();
  ByteString expected_result =
      "\xe7\x01\xdd\xd0\xbd\x1f\x9c\xd2\x96\x9e\x5b\xe8\x6e\x85\x8d\x97\x6f\x7b"
      "\x8d\x59\x4c\x75\x6d\x77\xbc\x59\xbf\x38\xe7\xe1\x98\xfa";
  SC_CHECK(out == expected_result);
  SC_LOG(INFO) << "Finished Sha256MerkleSpeedTest";
}

}  // namespace
}  // namespace uefi_crypto
}  // namespace wasm
}  // namespace sealed

int main() {
  sealed::wasm::uefi_crypto::Sha256HelloTest();
  sealed::wasm::uefi_crypto::Sha256MerkleSpeedTest();
  SC_LOG(INFO) << "PASSED";
  return 0;
}
