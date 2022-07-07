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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_TEST_SC_TEST_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_TEST_SC_TEST_H_

// Utilities to simplify writing Sealed Computing tests.

#include <ostream>

#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/status.h"
#include "third_party/sealedcomputing/wasm3/statusor.h"

namespace sealed {
namespace wasm {

// These magic operators are needed by the gtest suite.
inline std::ostream& operator<<(std::ostream& os, const ByteString& bytes) {
  return os << bytes.string();
}

// These magic operators are needed by the gtest suite.
inline std::ostream& operator<<(std::ostream& os, const Status& status) {
  return os << StatusCodeToString(status.code())
            << " Error message: " << status.message();
}

template <typename T>
inline std::ostream& operator<<(std::ostream& os, const StatusOr<T>& status) {
  if (status.ok()) {
    return os << *status;
  }
  return os << status.status();
}

}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_TEST_SC_TEST_H_
