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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_UEFI_CRYPTO_AES_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_UEFI_CRYPTO_AES_H_

#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/statusor.h"

namespace sealed {
namespace wasm {
namespace uefi_crypto {

constexpr size_t kAesGcmNonceLength = 12;
constexpr size_t kAesGcmTagLength = 16;
constexpr size_t kAes128KeyLength = 16;
constexpr size_t kAes256KeyLength = 32;
constexpr size_t kAesBlockSize = 16;

// Encrypt `plaintext` using `key`, and bound to `associated_data`.  The
// `nonce` MUST be unique for all different messages encrypted with `key`.
// Return a ByteString consisting of ciphertext + tag, which is bytes of
// ciphertext equal in length to plaintext + 16 bytes for the tag.  If any input
// parameter has an invalid size, return a kIllegalArgument error.
StatusOr<ByteString> AesGcmEncrypt(const ByteString& key,
                                   const ByteString& nonce,
                                   const SecretByteString& plaintext,
                                   const ByteString& associated_data);

// Recover the plaintext of a message encrypted with AesGcmEncrypt above.
StatusOr<SecretByteString> AesGcmDecrypt(const ByteString& key,
                                         const ByteString& nonce,
                                         const ByteString& ciphertext,
                                         const ByteString& associated_data);

// Encrypt a raw 16-byte block with the AES block encryption algorithm.  This
// has few use cases, other than as a primitive for buiding other AES-based
// cipher modes, such as AES-CTR, or perhaps wrapping secrets that are already
// indistinguishable from random.
void AesEncryptBlock(const ByteString& key, const ByteString& in,
                     ByteString* out);

// Decrypt a raw 16-byte block with the AES block decryption algorithm.
void AesDecryptBlock(const ByteString& key, const ByteString& in,
                     SecretByteString* out);

}  // namespace uefi_crypto
}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_UEFI_CRYPTO_AES_H_
