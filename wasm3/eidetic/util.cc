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

#include "third_party/sealedcomputing/wasm3/eidetic/util.h"

#include <endian.h>

#include <cstddef>
#include <cstdint>
#include <string>

#include "third_party/openssl/boringssl/src/include/openssl/sha.h"
#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/enforcer/crypto_internal.h"
#include "third_party/sealedcomputing/wasm3/enforcer/provisioning_service.common.h"
#include "third_party/sealedcomputing/wasm3/enforcer/securebox.h"
#include "third_party/sealedcomputing/wasm3/keyset_policies/p256_sign.h"
#include "third_party/sealedcomputing/wasm3/status.h"
#include "third_party/sealedcomputing/wasm3/statusor.h"

namespace sealed {
namespace eidetic {

using ::sealed::wasm::EideticConfig;
using ::sealed::wasm::kInvalidArgument;
using ::sealed::wasm::kUnauthenticated;
using ::sealed::wasm::Status;
using ::sealed::wasm::StatusOr;

namespace {
constexpr size_t kSHA256HashLen = 32;

// Size of the message signed in an Eidetic block.
constexpr size_t kPayloadSize =
    4 * kSHA256HashLen +    // challenges, states, prev_block, rand_bytes
    3 * sizeof(uint64_t) +  // time, time_delta, counter
    sizeof(bool);           // is_prepare

constexpr char kEideticSignatureInfo[] = "Eidetic block signature";

constexpr char kEideticProvisionPrefix[] = "Eidetic provision";

void CombineHashes(const std::string& left_hash, const std::string& right_hash,
                   std::string* out) {
  out->resize(kSHA256HashLen);
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, static_cast<const void*>(left_hash.data()),
                kSHA256HashLen);
  SHA256_Update(&ctx, static_cast<const void*>(right_hash.data()),
                kSHA256HashLen);
  SHA256_Final(reinterpret_cast<uint8_t*>(out->data()), &ctx);
}

void CombineWithPrefix(const std::string& prefix, const std::string& lhs,
                       const std::string& rhs, std::string* out) {
  out->resize(kSHA256HashLen);
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, static_cast<const void*>(prefix.data()), prefix.size());
  SHA256_Update(&ctx, static_cast<const void*>(lhs.data()), lhs.size());
  SHA256_Update(&ctx, static_cast<const void*>(rhs.data()), rhs.size());
  SHA256_Final(reinterpret_cast<uint8_t*>(out->data()), &ctx);
}

// TODO(b/259953374): remove this.
// Nanolibc memcmp uses signed char comparison which is inconsistent with
// how hashes are ordered when generating Eidetic merkle proofs.
// Here we use a simple memcmp implementation that uses unsigned char
// comparison.
int Memcmp(const void* p1, const void* p2, size_t n) {
  auto s1 = static_cast<const unsigned char*>(p1);
  auto s2 = static_cast<const unsigned char*>(p2);
  while (n > 0) {
    if (*s1 != *s2) return *s1 - *s2;
    s1++;
    s2++;
    n--;
  }
  return 0;
}

bool HashesLessThan(const std::string& hash1, const std::string& hash2) {
  return Memcmp(hash1.data(), hash2.data(), kSHA256HashLen) < 0;
}

void CombineHashesOrdered(const std::string& left_hash,
                          const std::string& right_hash, std::string* out) {
  if (HashesLessThan(left_hash, right_hash)) {
    CombineHashes(left_hash, right_hash, out);
  } else {
    CombineHashes(right_hash, left_hash, out);
  }
}

void StoreLittleEndian(uint8_t* p, uint64_t value) {
  uint64_t value_le = htole64(value);
  memcpy(p, &value_le, sizeof(uint64_t));
}

wasm::StatusOr<wasm::ByteString> DigestFromEideticBlock(
    const EideticBlock& block) {
  std::string buf = kEideticSignatureInfo;
  size_t info_size = buf.size();
  buf.resize(buf.size() + kPayloadSize);
  uint8_t* p = reinterpret_cast<uint8_t*>(buf.data()) + info_size;
  if (block.challenges_root.size() != kSHA256HashLen ||
      block.states_root.size() != kSHA256HashLen ||
      block.prev_block_hash.size() != kSHA256HashLen ||
      block.rand_bytes.size() != kSHA256HashLen) {
    return wasm::Status(wasm::kInvalidArgument,
                        "invalid block field: incorrect length");
  }
  memcpy(p, block.challenges_root.data(), kSHA256HashLen);
  p += kSHA256HashLen;
  memcpy(p, block.states_root.data(), kSHA256HashLen);
  p += kSHA256HashLen;
  memcpy(p, block.prev_block_hash.data(), kSHA256HashLen);
  p += kSHA256HashLen;
  memcpy(p, block.rand_bytes.data(), kSHA256HashLen);
  p += kSHA256HashLen;
  StoreLittleEndian(p, block.time_microseconds);
  p += sizeof(uint64_t);
  StoreLittleEndian(p, block.time_delta_microseconds);
  p += sizeof(uint64_t);
  StoreLittleEndian(p, block.counter);
  p += sizeof(uint64_t);
  char is_prepare = '\0';
  memcpy(p, &is_prepare, sizeof(char));
  return wasm::enforcer::Sha256::Digest(buf);
}
}  // namespace

bool VerifyMerkleProof(const std::vector<std::string>& proof,
                       const std::string& root, const std::string& leaf) {
  std::string last_hash = leaf;
  for (size_t i = 0; i < proof.size(); ++i) {
    CombineHashesOrdered(last_hash, proof.at(i), &last_hash);
  }
  return last_hash == root;
}

std::string LeafHashFromEideticIdAndState(const std::string& eidetic_id,
                                          const std::string& state,
                                          uint64_t version) {
  std::string state_and_version(kSHA256HashLen + sizeof(uint64_t), '\0');
  memcpy(state_and_version.data(), state.data(), state.size());
  uint64_t version_le = htole64(version);
  memcpy(state_and_version.data() + kSHA256HashLen, &version_le,
         sizeof(uint64_t));
  std::string digest;
  CombineWithPrefix("leaf:", eidetic_id, state_and_version, &digest);
  return digest;
}

std::string LeafHashFromChallenge(const std::string& challenge) {
  std::string digest;
  CombineWithPrefix("leaf:", challenge, "", &digest);
  return digest;
}

wasm::StatusOr<bool> VerifyEideticBlock(const std::string& pubkey,
                                        const EideticBlock& block) {
  SC_ASSIGN_OR_RETURN(auto p256_pubkey,
                      wasm::enforcer::P256PublicKey::Deserialize(pubkey));
  if (block.signature.size() != ECDSA_NBYTES) {
    return wasm::Status(wasm::kInvalidArgument, "invalid block signature");
  }
  auto signature = wasm::enforcer::EcdsaSig::Deserialize(block.signature);
  SC_ASSIGN_OR_RETURN(wasm::ByteString digest, DigestFromEideticBlock(block));
  return p256_pubkey.EcdsaVerify(digest, signature);
}

wasm::StatusOr<wasm::ByteString> EncryptMacKey(
    const std::string& pubkey, const std::string& eidetic_id,
    const wasm::SecretByteString& mac_key) {
  return wasm::enforcer::securebox::Encrypt(
      wasm::enforcer::securebox::kVersion2, pubkey, eidetic_id,
      kEideticProvisionPrefix, mac_key);
}

wasm::StatusOr<ProvisionRequest> CreateProvisionRequest(
    const EideticConfig& eidetic_config, const std::string& eidetic_id,
    const std::string& challenge, const wasm::SecretByteString& mac_key,
    const std::vector<std::string>& provisioning_challenges,
    const std::string& public_key, const wasm::P256Sign* signer) {
  ProvisionRequest request;
  request.eidetic_id = eidetic_id;
  request.quorum_public_keys = eidetic_config.signature_public_keys;
  request.challenge = challenge;
  size_t i = 0;
  for (const auto& pubkey : eidetic_config.hybrid_encryption_public_keys) {
    SC_ASSIGN_OR_RETURN(std::string encrypted_mac_key,
                        eidetic::EncryptMacKey(pubkey, eidetic_id, mac_key));
    request.thm_encrypted_mac_secret.push_back(encrypted_mac_key);
    std::string signature;
    std::string message = eidetic_id + encrypted_mac_key +
                          provisioning_challenges[i] + public_key;
    wasm::Status status = signer->Sign(message, &signature);
    if (!status.ok()) {
      return status;
    }
    request.signatures.push_back(signature);
    request.provisioning_challenges.push_back(provisioning_challenges[i]);
    i++;
  }
  request.public_key = public_key;
  return request;
}

Status VerifyProvisionResponse(const EideticConfig& eidetic_config,
                               const ProvisionResponse& response,
                               const std::string& challenge) {
  if (eidetic_config.signature_public_keys.size() !=
      response.provision_responses.size()) {
    return Status(
        kInvalidArgument,
        "incomplete provision response: fewer responses than quorum members");
  }
  int count = 0;
  for (size_t i = 0; i < eidetic_config.signature_public_keys.size(); ++i) {
    const std::string& pubkey = eidetic_config.signature_public_keys[i];
    const SingleProvisionResponse& single_response =
        response.provision_responses[i];
    StatusOr<bool> block_verified =
        VerifyEideticBlock(pubkey, single_response.eidetic_block);
    if (!block_verified.ok() || !*block_verified) {
      SC_LOG(ERROR) << "VerifyProvisionResponse: Error verifying Eidetic block "
                       "from pubkey: "
                    << wasm::ByteString(pubkey).hex();
      continue;
    }
    if (!VerifyMerkleProof(single_response.challenge_merkle_proof,
                           single_response.eidetic_block.challenges_root,
                           LeafHashFromChallenge(challenge))) {
      SC_LOG(ERROR)
          << "VerifyProvisionResponse: Error verifying challenge Merkle proof "
             "from pubkey: "
          << wasm::ByteString(pubkey).hex();
      continue;
    }
    ++count;
  }
  if (count >= eidetic_config.threshold) {
    return Status();
  } else {
    return Status(kUnauthenticated, "did not meet threshold responses");
  }
}

Status ValidateEideticConfig(const EideticConfig& eidetic_config) {
  if (eidetic_config.signature_public_keys.size() !=
      eidetic_config.hybrid_encryption_public_keys.size()) {
    return Status(kInvalidArgument,
                  "invalid eidetic config: size of signature_public_keys does "
                  "not match size of hybrid_encryption_public_keys");
  }
  int32_t size = eidetic_config.signature_public_keys.size();
  if (size == 0) {
    return Status();
  }
  // If size is non-zero then threshold must be <= size and > 0.
  if (eidetic_config.threshold > size || eidetic_config.threshold <= 0) {
    return Status(kInvalidArgument,
                  "invalid eidetic config: invalid threshold");
  }
  return Status();
}

}  // namespace eidetic
}  // namespace sealed
