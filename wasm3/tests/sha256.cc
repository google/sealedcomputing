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
#include <string>

#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/crypto.h"
#include "third_party/sealedcomputing/wasm3/logging.h"

using sealed::wasm::ByteString;
using sealed::wasm::Sha256;

extern "C" int start() {
  SC_CHECK_OK_AND_ASSIGN(
      const ByteString expected1,
      ByteString::Hex(
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
  Sha256 sha;
  ByteString digest = sha.Final();
  SC_CHECK_EQ(digest, expected1);
  digest = sha.Final();
  SC_CHECK_EQ(digest, expected1);

  SC_CHECK_OK_AND_ASSIGN(
      const ByteString expected2,
      ByteString::Hex(
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
  digest = Sha256::Digest("abc");
  SC_CHECK_EQ(digest, expected2);

  sha.Clear();
  sha.Update("a");
  sha.Update("b");
  sha.Update("c");
  digest = sha.Final();
  SC_CHECK_EQ(digest, expected2);

  return 0;
}
