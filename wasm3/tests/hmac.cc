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
using sealed::wasm::HmacSha256;
using sealed::wasm::SecretByteString;

extern "C" int start() {
  // Tests from https://tools.ietf.org/html/rfc4231.html
  {
    // 4.2.  Test Case 1
    SC_CHECK_OK_AND_ASSIGN(
        const SecretByteString key,
        SecretByteString::Hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"));
    const ByteString data("Hi There");
    SC_CHECK_OK_AND_ASSIGN(const ByteString expected,
                           ByteString::Hex("b0344c61d8db38535ca8afceaf0bf12b881"
                                           "dc200c9833da726e9376c2e32cff7"));
    HmacSha256 hmac(key);
    hmac.Update(data);
    {
      const ByteString result = hmac.Final();
      SC_CHECK_EQ(result, expected);
    }
    {
      const ByteString result = hmac.Final();
      SC_CHECK_EQ(result, expected);
    }
    SC_CHECK_EQ(HmacSha256::Digest(key, data), expected);
  }
  {
    // 4.3.  Test Case 2
    const SecretByteString key("Jefe");
    const ByteString data("what do ya want for nothing?");
    SC_CHECK_OK_AND_ASSIGN(const ByteString expected,
                           ByteString::Hex("5bdcc146bf60754e6a042426089575c75a0"
                                           "03f089d2739839dec58b964ec3843"));
    HmacSha256 hmac(key);
    hmac.Update(data);
    const ByteString result = hmac.Final();
    SC_CHECK_EQ(result, expected);
    SC_CHECK_EQ(HmacSha256::Digest(key, data), expected);
  }
  {
    // 4.3.  Test Case 2 (multiple update)
    const SecretByteString key("Jefe");
    const ByteString data1("what do");
    const ByteString data2(" ya want");
    const ByteString data3(" for nothing?");
    SC_CHECK_OK_AND_ASSIGN(const ByteString expected,
                           ByteString::Hex("5bdcc146bf60754e6a042426089575c75a0"
                                           "03f089d2739839dec58b964ec3843"));
    HmacSha256 hmac(key);
    hmac.Update(data1);
    hmac.Update(data2);
    hmac.Update(data3);
    const ByteString result = hmac.Final();
    SC_CHECK_EQ(result, expected);
  }

  return 0;
}
