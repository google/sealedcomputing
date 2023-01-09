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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_EIDETIC_UTIL_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_EIDETIC_UTIL_H_

#include <string>
#include <vector>

#include "third_party/sealedcomputing/wasm3/eidetic/service.common.h"
#include "third_party/sealedcomputing/wasm3/enforcer/provisioning_service.common.h"
#include "third_party/sealedcomputing/wasm3/keyset_policies/p256_sign.h"

namespace sealed {
namespace eidetic {

// Outputs the result of verifying `proof` as asserting the inclusion of `leaf`
// in `root`.
// Precondition: `leaf` and `root` are 32-byte hash outputs.
bool VerifyMerkleProof(const std::vector<std::string>& proof,
                       const std::string& root, const std::string& leaf);

// Returns the leaf hash used by Eidetic for a given `eidetic_id`, `state` and
// `version`.
std::string LeafHashFromEideticIdAndState(const std::string& eidetic_id,
                                          const std::string& state,
                                          uint64_t version);

// Returns the leaf hash used by Eidetic for a given `challenge`.
std::string LeafHashFromChallenge(const std::string& challenge);

// Verify the signature in an Eidetic block.
// `pubkey` is the 65-byte P256 public key in X9.62 format for the Eidetic node
// that signed the block.
// Returns a non-OK status if there is an error parsing the pubkey or block
// fields, and false if the signature verification fails.
wasm::StatusOr<bool> VerifyEideticBlock(const std::string& pubkey,
                                        const EideticBlock& block);

// Encrypts `mac_key` to an Eidetic node identified by `pubkey`.
wasm::StatusOr<wasm::ByteString> EncryptMacKey(
    const std::string& pubkey, const std::string& eidetic_id,
    const wasm::SecretByteString& mac_key);

// Creates a request for provisioning an Eidetic quorum.
wasm::StatusOr<ProvisionRequest> CreateProvisionRequest(
    const wasm::EideticConfig& eidetic_config, const std::string& eidetic_id,
    const std::string& challenge, const wasm::SecretByteString& mac_key,
    const std::vector<std::string>& provisioning_challenges,
    const std::string& public_key, const sealed::wasm::P256Sign* signer);

// Verifies a response from provisioning an Eidetic quorum.
// Non-OK status implies verification failed which implies a threshold number
// of valid responses from quorum members were not met.
// Causes of an invalid quorum member response include
// - error parsing Eidetic block
// - signature check on Eidetic block failed
// - challenge merkle proof verification failed
wasm::Status VerifyProvisionResponse(const wasm::EideticConfig& eidetic_config,
                                     const ProvisionResponse& response,
                                     const std::string& challenge);

// Returns an INVALID_ARGUMENT error status if `eidetic_config` is invalid.
wasm::Status ValidateEideticConfig(const wasm::EideticConfig& eidetic_config);

}  // namespace eidetic
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_EIDETIC_UTIL_H_
