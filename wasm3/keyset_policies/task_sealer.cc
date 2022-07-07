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

#include "third_party/sealedcomputing/wasm3/keyset_policies/task_sealer.h"

#include "third_party/sealedcomputing/rpc/encode_decode_lite.h"
#include "third_party/sealedcomputing/wasm3/enforcer/crypto_internal.h"

namespace sealed {
namespace wasm {
namespace {

std::string ToString(const ByteString& bs) {
  return std::string(reinterpret_cast<const char*>(bs.data()), bs.size());
}

ByteString SerializeAdditionalData(const ByteString& aad,
                                   const ByteString& task_config) {
  ::sealed::rpc::Encoder encoder;
  encoder.String(ToString(aad));
  encoder.String(ToString(task_config));
  return enforcer::Sha256::Digest(encoder.Finish());
}

}  // namespace

StatusOr<std::unique_ptr<TaskSealer>> TaskSealer::Create(
    std::unique_ptr<Sealer> base_sealer,
    const ByteString& serialized_task_config) {
  return std::unique_ptr<TaskSealer>(
      new TaskSealer(std::move(base_sealer), serialized_task_config));
}

ByteString TaskSealer::Encrypt(const ByteString& plaintext,
                               const ByteString& aad) {
  return base_sealer_->Encrypt(
      plaintext, SerializeAdditionalData(aad, serialized_task_config_));
}

bool TaskSealer::Decrypt(const ByteString& ciphertext, const ByteString& aad,
                         ByteString* plaintext) {
  return base_sealer_->Decrypt(
      ciphertext, SerializeAdditionalData(aad, serialized_task_config_),
      plaintext);
}

TaskSealer::TaskSealer(std::unique_ptr<Sealer> base_sealer,
                       const ByteString& serialized_task_config)
    : base_sealer_(std::move(base_sealer)),
      serialized_task_config_(serialized_task_config) {}

}  // namespace wasm
}  // namespace sealed
