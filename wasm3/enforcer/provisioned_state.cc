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

#include "third_party/sealedcomputing/wasm3/enforcer/provisioned_state.h"

#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/enforcer/crypto_internal.h"
#include "third_party/sealedcomputing/wasm3/enforcer/hybrid_encryption.h"
#include "third_party/sealedcomputing/wasm3/enforcer/provisioning_service.common.h"
#include "third_party/sealedcomputing/wasm3/enforcer/uefi_snp_guest/kdf.h"
#include "third_party/sealedcomputing/wasm3/handshaker.h"
#include "third_party/sealedcomputing/wasm3/keyset_policies/emulated_sealer.h"
#include "third_party/sealedcomputing/wasm3/keyset_policies/external_sealer.h"
#include "third_party/sealedcomputing/wasm3/keyset_policies/p256_sign.h"
#include "third_party/sealedcomputing/wasm3/keyset_policies/task_sealer.h"
#include "third_party/sealedcomputing/wasm3/status.h"
#include "third_party/sealedcomputing/wasm3/statusor.h"

namespace sealed {
namespace wasm {

namespace {

constexpr size_t kSecretLen = 32;

// Common salt used when deriving sub-secrets from pre-secret.
constexpr char kCommonHKDFSalt[] = "sealed computing v0 HKDF salt";
// Info string used to derive signing key secret from pre-secret.
constexpr char kSigningHKDFInfo[] =
    "HKDF info: sealed computing v0: signing keys";
// Info string used to derive group secret from shared group pre-secret.
constexpr char kGroupSecretHkDFInfo[] =
    "HKDF info: sealed computing v0: group secret";
// Info string used to derive HMAC secret from pre-secret.
constexpr char kHMACInfo[] = "HKDF info: sealed computing v0: HMAC";
// Info string used to derive BaseSealer key from hardware-bound secret for
// SEALER_TYPE_CPU.
constexpr char kSealerHKDFInfo[] = "HKDF info: sealed computing v0: cpu sealer";

}  // namespace

Status ProvisionedState::SetTaskConfig(const SealedTaskConfig& task_config,
                                       const SecretByteString& external_key) {
  task_config_ = task_config;
  return DeriveTaskSealer(external_key);
}

void ProvisionedState::SetTaskProvisionedState(
    const SecretByteString& task_pre_secret) {
  task_pre_secret_ = task_pre_secret;
  DeriveTaskKeys();
}

void ProvisionedState::SetGroupProvisionedState(
    const SecretByteString& group_pre_secret,
    const SealedGroupConfig& group_config) {
  group_pre_secret_ = group_pre_secret;
  group_config_ = group_config;
  DeriveGroupKeys();
}

void ProvisionedState::DeriveTaskKeys() {
  std::string hkdf_info = kSigningHKDFInfo;
  ByteString encoded_sealed_task =
      EncodeSealedTaskConfig(task_config_).public_data;
  hkdf_info.append(encoded_sealed_task);
  SecretByteString signing_key_secret =
      enforcer::Hkdf(kSecretLen, task_pre_secret_, kCommonHKDFSalt, hkdf_info);
  task_handshake_signer_ =
      P256Sign::CreateFromSecret(signing_key_secret, kHandshakeSigningPurpose);
  task_bytecode_signer_ =
      P256Sign::CreateFromSecret(signing_key_secret, kBytecodeSigningPurpose);
  task_eidetic_provision_request_signer_ = P256Sign::CreateFromSecret(
      signing_key_secret, kProvisionRequestSigningPurpose);
  hkdf_info = kHMACInfo;
  hkdf_info.append(encoded_sealed_task);
  task_hmac_key_ =
      enforcer::Hkdf(kSecretLen, task_pre_secret_, kCommonHKDFSalt, hkdf_info);
}

void ProvisionedState::DeriveGroupKeys() {
  std::string hkdf_info = kGroupSecretHkDFInfo;
  hkdf_info.append(EncodeSealedGroupConfig(group_config_).public_data);
  SecretByteString group_secret =
      enforcer::Hkdf(kSecretLen, group_pre_secret_, kCommonHKDFSalt, hkdf_info);
  group_he_privkey_ = std::unique_ptr<HybridEncryptionPrivateKey>(
      new EciesX25519PrivateKey(group_secret));
  group_p256_privkey_ = std::make_unique<EciesP256PrivateKey>(group_secret);
}

Status ProvisionedState::DeriveTaskSealer(
    const SecretByteString& external_key) {
  std::unique_ptr<Sealer> base_sealer;
  switch (task_config_.sealer_type) {
    case SealerType::SEALER_TYPE_TEST:
      base_sealer = std::unique_ptr<Sealer>(EmulatedSealer::Create().release());
      break;
    case SealerType::SEALER_TYPE_EXTERNAL: {
      auto res = ExternalSealer::Create(
          std::make_unique<enforcer::AesGcm>(external_key));
      SC_CHECK_OK(res);
      base_sealer = std::unique_ptr<Sealer>(res->release());
      break;
    }
    case SealerType::SEALER_TYPE_CPU: {
      SC_ASSIGN_OR_RETURN(SecretByteString cpu_bound_secret,
                          enforcer::GetSevSnpSealingKey());
      // Derive a key bound to (SEV-SNP KDF output, Sealer purpose).
      SecretByteString key =
          enforcer::Hkdf(enforcer::kAes128KeyLength, cpu_bound_secret,
                         kCommonHKDFSalt, kSealerHKDFInfo);
      SC_ASSIGN_OR_RETURN(
          auto res,
          ExternalSealer::Create(std::make_unique<enforcer::AesGcm>(key)));
      base_sealer = std::unique_ptr<Sealer>(res.release());
      break;
    }
    default:
      SC_LOG(FATAL) << "Unexpected sealer type";
  }
  SC_CHECK(!!base_sealer);
  auto res = TaskSealer::Create(std::move(base_sealer),
                                EncodeSealedTaskConfig(task_config_));
  SC_CHECK_OK(res);
  sealer_ = std::move(*res);
  return Status::OkStatus();
}

}  // namespace wasm
}  // namespace sealed
