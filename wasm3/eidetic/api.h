//  Copyright 2021 Google LLC.
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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_EIDETIC_API_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_EIDETIC_API_H_

#include <optional>
#include <string>

#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/eidetic/service.common.h"
#include "third_party/sealedcomputing/wasm3/enforcer/provisioning_service.common.h"
#include "third_party/sealedcomputing/wasm3/statusor.h"

namespace sealed {
namespace eidetic {

struct EideticState {
  static constexpr uint32_t kStateSize = 32;

  // Must be kStateSize bytes long. Usually the output of a hash function on the
  // state committed to Eidetic.
  std::string digest;
  // Every mutation to `digest` must increment this counter.
  uint64_t version = 0;
};

class EideticQuorum {
 public:
  virtual ~EideticQuorum() = default;

  // Calls Eidetic.Read on each quorum member.
  // Returns as soon as a threshold number of calls succeed.
  // Returns the consensus state in the quorum (and updates internal state_).
  // Error status returned when a consensus is not available and retrying
  // is unlikely to change that.
  virtual wasm::StatusOr<std::string> ReadConsensus();

  // Attempts to create a consensus when it is not available.
  // Calls ReadNewest and WriteConsensus with the result (which is also
  // returned).
  wasm::StatusOr<std::string> HealConsensus();

  // Calls Eidetic.Write with (new_state, state_.version + 1) on every quorum
  // member.
  // Internal state_ must be initialized (i.e. by calling ReadConsensus)
  // otherwise a FAILED_PRECONDITION status is returned.
  // Returns as soon as a threshold number of calls succeed. Error status
  // returned otherwise, in which case,
  // - retrying is unlikely to succeed,
  // - the possible resulting quorum state includes:
  //     - no consensus is available, or
  //     - the consensus is not (new_state, version_ + 1), or
  //     - the consensus is (new_state, version_ + 1) but confirming responses
  //       failed in transit.
  virtual wasm::Status WriteConsensus(const std::string& new_state);

 protected:
  // Calls Eidetic.Read on every quorum member.
  // Returns when each call is in a terminal state and, in the case of failure,
  // retrying is unlikely to succeed.
  // Returns the newest state seen across all calls.
  // Error status returned when every Read call fails.
  wasm::StatusOr<EideticState> ReadNewest();

  // Like WriteConsensus above but writes a version too.
  wasm::Status WriteConsensus(const EideticState& new_state);

  std::optional<EideticState> state_;
};

// Computes MAC for EideticWrite. For testing only.
wasm::ByteString ComputeMacForTesting(const wasm::SecretByteString& mac_key,
                                      const std::string& eidetic_id,
                                      const std::string& state,
                                      uint64_t version);

// Verify responses from Eidetic. For testing only.
wasm::StatusOr<EideticState> VerifySingleResponsesForTesting(
    const wasm::EideticConfig& eidetic_config, const std::string& eidetic_id,
    const std::string& challenge, const std::vector<SingleResponse>& responses);

}  // namespace eidetic
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_EIDETIC_API_H_
