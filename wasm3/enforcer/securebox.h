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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_SECUREBOX_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_SECUREBOX_H_

#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/statusor.h"

namespace sealed {
namespace wasm {
namespace enforcer {
namespace securebox {

// We're considering a V3 version, likely using curve25519, and binding the
// public key so that we're CCA secure, which is not the case for V2.
enum Version {
  kVersion2 = 2,
};

// Functions for generating keys.  For version 2, keys are NIST secp256r1,
// encoded like OpenSSL.  The private key is 32 bytes, BigEndian.  The public
// key is 0x4 + 32-byte X + 32-byte Y, BigEndian.
StatusOr<SecretByteString> RandomPrivkey(Version version);

// This is a KDF for generating private keys from a secret seed.  `info` should
// describe the purpose of the key.
StatusOr<SecretByteString> PrivkeyFromSeed(Version version,
                                           const SecretByteString& seed,
                                           const ByteString& info);

// Derive the public key from the private key.
StatusOr<ByteString> PubkeyFromPrivkey(Version version,
                                       const SecretByteString& privkey);

// Either `pubkey` or `shared_secret` must be non-empty.  This supports both
// symmetric and public-key encryption.
StatusOr<ByteString> Encrypt(Version version, const ByteString& pubkey,
                             const SecretByteString& shared_secret,
                             const ByteString& info,
                             const SecretByteString& plaintext);

// Either `privkey` or `shared_secret` must be non-empty.  This supports both
// symmetric and public-key encryption.
StatusOr<SecretByteString> Decrypt(Version version,
                                   const SecretByteString& privkey,
                                   const SecretByteString& shared_secret,
                                   const ByteString& info,
                                   const ByteString& ciphertext);

}  // namespace securebox
}  // namespace enforcer
}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_SECUREBOX_H_
