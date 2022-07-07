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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_HYBRID_ENCRYPTION_TINK_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_HYBRID_ENCRYPTION_TINK_H_

#include "third_party/absl/status/statusor.h"
#include "third_party/sealedcomputing/wasm3/enforcer/hybrid_encryption.h"
#include "third_party/tink/cc/keyset_handle.h"

namespace sealed::wasm {

// This translates a public key as exported by HybridEncryptionPrivateKey to the
// appropriate (binary) serialized Tink Keyset containing a
// EciesAeadHkdfPublicKey.
absl::StatusOr<std::string> GetTinkPublicKeyset(const std::string& pubkey);

// Extracts and returns the raw X25519 public value in
// `serialized_tink_public_keyset` containing a EciesAeadHkdfPublicKey with
// EciesX25519HkdfHmacSha256Aes256Gcm format. This raw public value is intended
// to be used in HybridEncryptionPublicKey.
absl::StatusOr<std::string> GetRawPublicValueFromTinkPublicKeyset(
    const std::string& serialized_tink_public_keyset);

// Adds the 5-byte Tink prefix to a ciphertext returned by
// HybridEncryptionPublicKey::Encrypt, making it Tink-compatible i.e.
// decryptable by a Tink EciesAeadHkdfPrivateKey with the
// EciesX25519HkdfHmacSha256Aes256Gcm format.
absl::StatusOr<std::string> AddTinkPrefixToCiphertext(
    const std::string& serialized_tink_public_keyset,
    const std::string& ciphertext);

}  // namespace sealed::wasm

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_HYBRID_ENCRYPTION_TINK_H_
