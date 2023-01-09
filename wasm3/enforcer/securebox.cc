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

#include "third_party/sealedcomputing/wasm3/enforcer/securebox.h"

#include "third_party/sealedcomputing/wasm3/crypto.h"
#include "third_party/sealedcomputing/wasm3/enforcer/crypto_internal.h"
#include "third_party/sealedcomputing/wasm3/status.h"
#include "third_party/sealedcomputing/wasm3/statusor.h"

namespace sealed {
namespace wasm {
namespace enforcer {
namespace securebox {

namespace {

// Compute the shared secret.  pubkey and privkey can be nullptr, in which case
// they are not used, and symmetric encryption is done with only shared_secret.
// Similarly, shared_secret may be empty, but either privkey or shared_secret
// must be non-empty.
StatusOr<SecretByteString> ComputeSharedKey(
    const EcPoint* pubkey, const Bignum* privkey,
    const SecretByteString& shared_secret) {
  char salt_data[] = {'S', 'E', 'C', 'U',       'R', 'E',
                      'B', 'O', 'X', kVersion2, '\0'};
  ByteString salt(salt_data, sizeof(salt_data));
  if ((pubkey == nullptr) != (privkey == nullptr)) {
    return Status(kInvalidArgument,
                  "pubkey and privkey must both exist, or both be nullptr.");
  }
  if (pubkey == nullptr) {
    ByteString hkdf_info("SHARED HKDF-SHA-256 AES-128-GCM");
    return Hkdf(kAes128KeyLength, shared_secret, ByteString(salt), hkdf_info);
  }
  if (!pubkey->IsValidPoint()) {
    return Status(kInvalidArgument, "Their public key is an invalid EC point.");
  }
  ByteString our_serialized_pubkey = pubkey->Serialize();
  EcPoint shared_point = *privkey * *pubkey;
  // Cut out the X coordinate from the serialized shared point.
  SecretByteString shared_x =
      shared_point.Serialize().substr(1, P256_SCALAR_NBYTES);
  ByteString hkdf_info("P256 HKDF-SHA-256 AES-128-GCM");
  return Hkdf(kAes128KeyLength, shared_x + shared_secret, ByteString(salt),
              hkdf_info);
}

}  // namespace

StatusOr<SecretByteString> RandomPrivkey(Version version) {
  if (version != kVersion2) {
    return Status(kInvalidArgument, "Only SecureBox version 2 is supported");
  }
  return P256PrivateKey().Serialize();
}

StatusOr<SecretByteString> PrivkeyFromSeed(Version version,
                                           const SecretByteString& seed,
                                           const ByteString& info) {
  if (version != kVersion2) {
    return Status(kInvalidArgument, "Only SecureBox version 2 is supported");
  }
  return P256PrivateKey(seed, info).Serialize();
}

StatusOr<ByteString> PubkeyFromPrivkey(Version version,
                                       const SecretByteString& privkey) {
  if (version != kVersion2) {
    return Status(kInvalidArgument, "Only SecureBox version 2 is supported");
  }
  P256PrivateKey privkey_int = P256PrivateKey::Deserialize(privkey);
  return privkey_int.GetPublicKey().Serialize();
}

StatusOr<ByteString> Encrypt(Version version, const ByteString& pubkey,
                             const SecretByteString& shared_secret,
                             const ByteString& info,
                             const SecretByteString& plaintext) {
  if (version != kVersion2) {
    return Status(kInvalidArgument, "Only SecureBox version 2 is supported");
  }
  if (plaintext.empty()) {
    return Status(kInvalidArgument, "Cannot encrypt empty payload");
  }
  ByteString eph_serialized_pubkey;
  SecretByteString shared_key;
  if (pubkey.empty()) {
    SC_ASSIGN_OR_RETURN(shared_key,
                        ComputeSharedKey(nullptr, nullptr, shared_secret));
  } else {
    StatusOr<P256PublicKey> server_pubkey = P256PublicKey::Deserialize(pubkey);
    if (!server_pubkey.ok())
      return Status(kInvalidArgument, "Encrypt error: invalid public key");
    P256PrivateKey eph_privkey;  // Generates a random public key.
    P256PublicKey eph_pubkey = eph_privkey.GetPublicKey();
    Bignum eph_d = eph_privkey.GetPrivateBignum();
    EcPoint server_point = server_pubkey->GetPublicEcPoint();
    SC_ASSIGN_OR_RETURN(shared_key,
                        ComputeSharedKey(&server_point, &eph_d, shared_secret));
    eph_serialized_pubkey = eph_pubkey.Serialize();
  }
  ByteString nonce = RandBytes(kAesGcmNonceLength);
  AesGcm aes_gcm(shared_key);
  char prefix[] = {kVersion2, 0};
  return ByteString(prefix, sizeof(prefix)) + eph_serialized_pubkey + nonce +
         aes_gcm.Encrypt(nonce, plaintext, info);
}

StatusOr<SecretByteString> Decrypt(Version version,
                                   const SecretByteString& privkey,
                                   const SecretByteString& shared_secret,
                                   const ByteString& info,
                                   const ByteString& ciphertext) {
  if (version != kVersion2) {
    return Status(kInvalidArgument, "Only SecureBox version 2 is supported");
  }
  if (ciphertext.size() < sizeof(uint16_t)) {
    return Status(kInvalidArgument, "Ciphertext too short");
  }
  if (ciphertext[0] != kVersion2 || ciphertext[1] != 0) {
    return Status(kInvalidArgument, "Ciphertext is not version 2");
  }
  size_t pos = 2;
  ByteString eph_serialized_pubkey;
  SecretByteString shared_key;
  if (privkey.empty()) {
    SC_ASSIGN_OR_RETURN(shared_key,
                        ComputeSharedKey(nullptr, nullptr, shared_secret));
  } else {
    if (ciphertext.size() - pos < P256_NBYTES) {
      return Status(kInvalidArgument, "Ciphertext too short");
    }
    ByteString eph_serialized_pubkey = ciphertext.substr(pos, P256_NBYTES);
    pos += P256_NBYTES;
    P256PrivateKey server_privkey = P256PrivateKey::Deserialize(privkey);
    Bignum server_d = server_privkey.GetPrivateBignum();
    StatusOr<EcPoint> eph_point =
        EcPoint::Deserialize(ByteString(eph_serialized_pubkey));
    if (!eph_point.ok())
      return Status(kInvalidArgument, "Invalid ciphertext");
    SC_ASSIGN_OR_RETURN(
        shared_key, ComputeSharedKey(&(*eph_point), &server_d, shared_secret));
  }
  if (ciphertext.size() - pos < kAesGcmNonceLength) {
    return Status(kInvalidArgument, "Ciphertext too short");
  }
  ByteString nonce = ciphertext.substr(pos, kAesGcmNonceLength);
  pos += kAesGcmNonceLength;
  ByteString payload = ciphertext.substr(pos);
  AesGcm aes_gcm(shared_key);
  return aes_gcm.Decrypt(nonce, payload, info);
}

}  // namespace securebox
}  // namespace enforcer
}  // namespace wasm
}  // namespace sealed
