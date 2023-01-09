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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_STATUS_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_STATUS_H_

// This status is similar to absl::Status, but this file does not transitively
// include hundreds of thousands of lines of imported header files which would
// too hard to security review.

#include <string>

namespace sealed {
namespace wasm {

#define SC_CHECK_OK(A) SC_CHECK(A.ok())

// This is identical to absl::StatusCode.
enum StatusCode : uint8_t {
  kOk = 0,
  kCancelled = 1,
  kUnknown = 2,
  kInvalidArgument = 3,
  kDeadlineExceeded = 4,
  kNotFound = 5,
  kAlreadyExists = 6,
  kPermissionDenied = 7,
  kResourceExhausted = 8,
  kFailedPrecondition = 9,
  kAborted = 10,
  kOutOfRange = 11,
  kUnimplemented = 12,
  kInternal = 13,
  kUnavailable = 14,
  kDataLoss = 15,
  kUnauthenticated = 16,
  kLast = kUnauthenticated,
};

// A status code which can be returned by an RPC.
class [[nodiscard]] Status {
 public:
  Status() : code_(kOk), error_message_() {}
  Status(StatusCode error_code, const std::string& error_message)
      : code_(error_code), error_message_(error_message) {}
  Status(const Status&) = default;
  Status(Status&&) = default;

  Status& operator=(const Status&) = default;
  Status& operator=(Status&&) = default;

  StatusCode code() const { return code_; }
  const std::string& message() const { return error_message_; }

  bool ok() const { return code() == kOk; }
  static Status OkStatus() { return Status(); }

  bool operator==(const Status& rhs) const;
  bool operator!=(const Status& rhs) const;
  bool operator==(StatusCode error_code) const;
  bool operator!=(StatusCode error_code) const;
  operator bool() const { return ok(); }

 private:
  StatusCode code_;
  std::string error_message_;
};

Status& GetStatus(Status& status);
const Status& GetStatus(const Status& status);

// Converts `code` into a human-readable string.
std::string StatusCodeToString(StatusCode code);

bool operator==(StatusCode error_code, const Status& status);
bool operator!=(StatusCode error_code, const Status& status);

#define SC_RETURN_IF_ERROR(expr)             \
  {                                          \
    ::sealed::wasm::Status _status = (expr); \
    if (!_status) {                          \
      return _status;                        \
    }                                        \
  }

// For use in gUnit tests only.
#define SC_ASSERT_OK(expr)                                        \
  {                                                               \
    auto status = (expr);                                         \
    if (!status.ok()) {                                           \
      FAIL() << "Asserting OK Status: Actual: "                   \
             << ::sealed::wasm::StatusCodeToString(status.code()) \
             << " with message: " << status.message();            \
    }                                                             \
  }

}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_STATUS_H_
