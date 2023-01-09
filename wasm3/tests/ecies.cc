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

#include "third_party/sealedcomputing/wasm3/builtin/crypto_wasm.h"
#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/logging.h"
#include "third_party/sealedcomputing/wasm3/statusor.h"

using sealed::wasm::ByteString;
using sealed::wasm::SecretByteString;

extern "C" int start() {
  {
    const SecretByteString expected_plaintext("plaintext");
    constexpr uint8_t context_info[] = "context_info";

    // Create the Ecies public and private key handles.
    auto pkey = biGenEciesX25519PrivateKey();
    auto pubkey = biEciesX25519PublicKeyFromPrivateKey(pkey);

    // Encrypt expected_plaintext. ciphertext should be the size of the
    // plaintext plus the size of an X25519 public value, an AES-GCM nonce, and
    // an AES-GCM tag.
    ByteString ciphertext(expected_plaintext.size() + 60);
    biEciesX25519AesGcmHkdfEncrypt(pubkey, expected_plaintext.data(),
                                   expected_plaintext.size(), context_info,
                                   sizeof(context_info), ciphertext.data());

    // Decrypt ciphertext.
    SecretByteString plaintext(expected_plaintext.size());
    SC_CHECK(biEciesX25519AesGcmHkdfDecrypt(
        pkey, ciphertext.data(), ciphertext.size(), context_info,
        sizeof(context_info), plaintext.data()));

    // Check that the plaintext matches.
    SC_CHECK_EQ(expected_plaintext, plaintext);

    // Release the public and private key handles.
    biDestroyEciesX25519PrivateKey(pkey);
    biDestroyEciesX25519PublicKey(pubkey);
  }

  return 0;
}
