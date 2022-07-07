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

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>

#include "third_party/sealedcomputing/wasm3/base.h"
#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/examples/e2e_authn/e2e_authn.common.h"
#include "third_party/sealedcomputing/wasm3/status.h"
#include "third_party/sealedcomputing/wasm3/statusor.h"

namespace sealed::e2e_authn::server {

using ::sealed::wasm::SecretByteString;
using ::sealed::wasm::Status;
using ::sealed::wasm::StatusOr;

namespace {

struct Vault {
  SecretByteString kf;
  SecretByteString recovery_key;
  const uint32_t bad_guess_limit = 10;

  // If 0 then recovery key is unrecoverable.
  // Resets to `max_bad_guess_counter` on a good guess.
  // Decrements by 1 on a bad guess.
  uint32_t bad_guesses_left = bad_guess_limit;
};

// Map from public ID to Vault.
std::unordered_map<std::string, Vault>* ServerScopedMap() {
  static auto* global_map = new std::unordered_map<std::string, Vault>();
  return global_map;
}

int CT_memcmp(const char* a, const uint8_t* b, size_t len) {
  uint8_t x = 0;
  for (size_t i = 0; i < len; i++) {
    x |= a[i] ^ b[i];
  }
  return x;
}

}  // namespace

StatusOr<EchoResponse> Echo(const EchoRequest& request) {
  return EchoResponse{request.request};
}

StatusOr<EnrollResponse> Enroll(const EnrollRequest& request) {
  if (ServerScopedMap()->find(request.recovery_key_identifier) !=
      ServerScopedMap()->end()) {
    return Status(sealed::wasm::kInvalidArgument, "id already registered");
  }
  ServerScopedMap()->insert(
      {request.recovery_key_identifier,
       {request.knowledge_factor, request.recovery_key, request.bad_guess_limit,
        request.bad_guess_limit}});
  return EnrollResponse();
}

StatusOr<OpenResponse> Open(const OpenRequest& request) {
  auto it = ServerScopedMap()->find(request.recovery_key_identifier);
  if (it == ServerScopedMap()->end()) {
    return Status(sealed::wasm::kInvalidArgument, "id not registered");
  }
  Vault& vault = it->second;
  if (vault.bad_guesses_left <= 0) {
    return Status(sealed::wasm::kFailedPrecondition, "no more guesses left");
  }
  if (request.knowledge_factor.size() == vault.kf.size() &&
      !CT_memcmp(request.knowledge_factor.data(), vault.kf.data(),
                 request.knowledge_factor.size())) {
    // Claim was correct, open the vault and reset the bad guess count.
    vault.bad_guesses_left = vault.bad_guess_limit;
    return OpenResponse{true, vault.recovery_key.string(),
                        vault.bad_guesses_left};
  }
  // Claim was not correct, count a bad guess.
  vault.bad_guesses_left--;
  return OpenResponse{false, "", vault.bad_guesses_left};
}

StatusOr<DecryptAndEchoResponse> DecryptAndEcho(
    const DecryptAndEchoRequest& request) {
  wasm::ByteString raw_ciphertext =
      request.ciphertext.substr(wasm::kTinkPrefixLength);
  SC_ASSIGN_OR_RETURN(
      wasm::SecretByteString plaintext,
      wasm::DecryptWithGroupKey(raw_ciphertext, /*context_info=*/""));
  return DecryptAndEchoResponse{plaintext.string()};
}

}  // namespace sealed::e2e_authn::server

WASM_EXPORT int start() {
  // Do server initialization here: i.e. initializing all server-scoped state.
  sealed::e2e_authn::server::ServerScopedMap();

  sealed::wasm::Serve();
  return 0;
}
