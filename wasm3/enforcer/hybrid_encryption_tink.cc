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

#include "third_party/sealedcomputing/wasm3/enforcer/hybrid_encryption_tink.h"

#include "net/proto2/util/public/message_differencer.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/sealedcomputing/wasm3/enforcer/hybrid_encryption.h"
#include "third_party/tink/cc/aead_key_templates.h"
#include "third_party/tink/cc/cleartext_keyset_handle.h"
#include "third_party/tink/cc/hybrid_config.h"
#include "third_party/tink/cc/hybrid_key_templates.h"
#include "third_party/tink/cc/keyset_handle.h"
#include "third_party/tink/proto/common.proto.h"
#include "third_party/tink/proto/ecies_aead_hkdf.proto.h"
#include "util/task/status_macros.h"

namespace sealed::wasm {

using crypto::tink::KeysetHandle;
using google::crypto::tink::EciesAeadHkdfPublicKey;
using google::crypto::tink::Keyset;
using google::crypto::tink::KeysetInfo;

namespace {

static constexpr uint8_t kTinkStartByte = 0x01;

void uint32_as_big_endian(uint32_t value, char* buf) {
  buf[0] = 0xff & (value >> 24);
  buf[1] = 0xff & (value >> 16);
  buf[2] = 0xff & (value >> 8);
  buf[3] = 0xff & (value >> 0);
}

}  // namespace

absl::StatusOr<std::string> GetTinkPublicKeysetFromEciesX25519PublicKey(
    const std::string& pubkey) {
  EciesAeadHkdfPublicKey he_pubkey;
  he_pubkey.set_version(0);
  he_pubkey.set_x(pubkey);
  auto params = he_pubkey.mutable_params();
  params->set_ec_point_format(google::crypto::tink::EcPointFormat::COMPRESSED);
  params->mutable_kem_params()->set_curve_type(
      google::crypto::tink::EllipticCurveType::CURVE25519);
  params->mutable_kem_params()->set_hkdf_hash_type(
      google::crypto::tink::HashType::SHA256);
  *(params->mutable_dem_params()->mutable_aead_dem()) =
      crypto::tink::AeadKeyTemplates::Aes256Gcm();

  // Create a keyset handle from the appropriate hybrid key template.
  RETURN_IF_ERROR(crypto::tink::HybridConfig::Register());
  ASSIGN_OR_RETURN(
      auto keyset_handle,
      KeysetHandle::GenerateNew(crypto::tink::HybridKeyTemplates::
                                    EciesX25519HkdfHmacSha256Aes256Gcm()));
  // Get public keyset handle.
  ASSIGN_OR_RETURN(auto public_keyset_handle,
                   keyset_handle->GetPublicKeysetHandle());
  // Access the cleartext keyset in public_keyset_handle.
  Keyset keyset =
      crypto::tink::CleartextKeysetHandle::GetKeyset(*public_keyset_handle);

  // Mutate keyset, adding the serialized EciesAeadHkdfPublicKey.
  for (auto& key : *keyset.mutable_key()) {
    if (key.key_id() == keyset.primary_key_id()) {
      key.mutable_key_data()->set_value(he_pubkey.SerializeAsString());
    }
  }
  return keyset.SerializeAsString();
}

absl::StatusOr<std::string> GetTinkPublicKeysetFromEciesP256PublicKey(
    const std::string& pubkey) {
  // take pubkey
  StatusOr<std::unique_ptr<EciesP256PublicKey>> ecies_pubkey =
      EciesP256PublicKey::Create(pubkey);
  if (!ecies_pubkey.ok()) {
    return absl::InvalidArgumentError(ecies_pubkey.message());
  }

  EciesAeadHkdfPublicKey he_pubkey;
  he_pubkey.set_version(0);
  he_pubkey.set_x((*ecies_pubkey)->GetX());
  he_pubkey.set_y((*ecies_pubkey)->GetY());
  auto params = he_pubkey.mutable_params();
  params->set_ec_point_format(google::crypto::tink::EcPointFormat::COMPRESSED);
  params->mutable_kem_params()->set_curve_type(
      google::crypto::tink::EllipticCurveType::NIST_P256);
  params->mutable_kem_params()->set_hkdf_hash_type(
      google::crypto::tink::HashType::SHA256);
  *(params->mutable_dem_params()->mutable_aead_dem()) =
      crypto::tink::AeadKeyTemplates::Aes128Gcm();

  // Create a keyset handle from the appropriate hybrid key template.
  RETURN_IF_ERROR(crypto::tink::HybridConfig::Register());
  ASSIGN_OR_RETURN(auto keyset_handle,
                   KeysetHandle::GenerateNew(
                       crypto::tink::HybridKeyTemplates::
                           EciesP256CompressedHkdfHmacSha256Aes128Gcm()));
  // Get public keyset handle.
  ASSIGN_OR_RETURN(auto public_keyset_handle,
                   keyset_handle->GetPublicKeysetHandle());
  // Access the cleartext keyset in public_keyset_handle.
  Keyset keyset =
      crypto::tink::CleartextKeysetHandle::GetKeyset(*public_keyset_handle);

  // Mutate keyset, adding the serialized EciesAeadHkdfPublicKey.
  for (auto& key : *keyset.mutable_key()) {
    if (key.key_id() == keyset.primary_key_id()) {
      key.mutable_key_data()->set_value(he_pubkey.SerializeAsString());
    }
  }
  return keyset.SerializeAsString();
}

absl::StatusOr<std::string> GetRawPublicValueFromTinkPublicKeyset(
    const std::string& serialized_tink_public_keyset) {
  ASSIGN_OR_RETURN(std::unique_ptr<KeysetHandle> public_keyset_handle,
                   KeysetHandle::ReadNoSecret(serialized_tink_public_keyset));
  Keyset keyset =
      crypto::tink::CleartextKeysetHandle::GetKeyset(*public_keyset_handle);

  for (auto& key : *keyset.mutable_key()) {
    if (key.key_id() != keyset.primary_key_id()) {
      continue;
    }
    if (key.key_data().type_url() !=
        "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey") {
      return absl::InvalidArgumentError(absl::StrCat(
          "unexpected key_data.type_url for primary key in given keyset: ",
          key.key_data().type_url()));
    }
    if (key.key_data().key_material_type() !=
        google::crypto::tink::KeyData_KeyMaterialType_ASYMMETRIC_PUBLIC) {
      return absl::InvalidArgumentError(absl::StrCat(
          "unexpected key_data.key_material_type in given keyset: ",
          key.key_data().key_material_type()));
    }
    EciesAeadHkdfPublicKey he_pubkey;
    if (!he_pubkey.ParseFromString(key.key_data().value())) {
      return absl::InvalidArgumentError(
          "could not parse EciesAeadHkdfPublicKey in given keyset");
    }
    const google::crypto::tink::KeyTemplate& key_template =
        crypto::tink::HybridKeyTemplates::EciesX25519HkdfHmacSha256Aes256Gcm();
    google::crypto::tink::EciesAeadHkdfKeyFormat key_format;
    key_format.ParseFromString(key_template.value());
    if (!proto2::util::MessageDifferencer::Equivalent(key_format.params(),
                                                      he_pubkey.params())) {
      return absl::InvalidArgumentError(
          "given keyset not does not match EciesX25519HkdfHmacSha256Aes256Gcm "
          "format");
    }
    return he_pubkey.x();
  }
  return absl::InvalidArgumentError(
      "given keyset does not have a key matching primary_key_id");
}

absl::StatusOr<std::string> AddTinkPrefixToCiphertext(
    const std::string& serialized_tink_public_keyset,
    const std::string& ciphertext) {
  ASSIGN_OR_RETURN(std::unique_ptr<KeysetHandle> public_keyset_handle,
                   KeysetHandle::ReadNoSecret(serialized_tink_public_keyset));
  const KeysetInfo& keyset_info = public_keyset_handle->GetKeysetInfo();
  std::string prefix;
  prefix.assign(reinterpret_cast<const char*>(&kTinkStartByte), 1);
  char key_id_buf[4];
  uint32_as_big_endian(keyset_info.primary_key_id(), key_id_buf);
  prefix.append(key_id_buf, 4);
  return absl::StrCat(prefix, ciphertext);
}

}  // namespace sealed::wasm
