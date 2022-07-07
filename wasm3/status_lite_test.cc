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

#include <memory>

#include "third_party/sealedcomputing/wasm3/logging.h"
#include "third_party/sealedcomputing/wasm3/status.h"

namespace sealed {
namespace wasm {
namespace {

Status TestStatus(bool make_error) {
  if (make_error) {
    return Status(kUnknown, "Something bad happened");
  }
  return Status::OkStatus();
}

// `make_error` causes an error status to be created.  `probe` is set to true if
// execution continues after SC_RETURN_IF_ERROR, and can be used to verify that
// RETURN_IF_ERROR returns on an error condition.
Status TestReturnIfErrorCase(bool make_error, bool& probe) {
  SC_RETURN_IF_ERROR(TestStatus(make_error));
  probe = true;
  return Status::OkStatus();
}

void TestDefaultStatus() {
  const Status status;
  SC_CHECK_EQ(status.code(), kOk);
  SC_CHECK(status.ok());
  SC_CHECK_OK(status);
  SC_CHECK(status == status);
  SC_CHECK_FALSE(status != status);
  SC_CHECK(status.message().empty());
  SC_LOG(INFO) << StatusCodeToString(status.code());
  // Test operator bool().
  if (!status) {
    SC_CHECK(false);
  }
}

void TestStatusOkWithMessage() {
  const Status status(kOk, "No Error");
  SC_CHECK_EQ(status.code(), kOk);
  SC_CHECK_OK(status);
  SC_CHECK(status != Status());
  SC_CHECK_FALSE(status == Status());
  SC_CHECK_NE(status, Status());
  SC_CHECK_EQ(status.message(), "No Error");
}

void TestStatusUnknown() {
  const Status status(kUnknown, "Something bad happened");
  SC_CHECK_EQ(status.code(), kUnknown);
  SC_CHECK_FALSE(status.ok());
  SC_CHECK_EQ(status, kUnknown);
  SC_CHECK_EQ(kUnknown, status);

  // Test operator bool().
  if (status) {
    SC_CHECK(false);
  }
}

// Test that SC_RETURN_IF_ERROR actually returns when returning an error, and
// does not return when the status is OK.
void TestReturnIfError() {
  bool probe = false;
  SC_CHECK_OK(TestReturnIfErrorCase(false, probe));
  SC_CHECK(probe);

  Status status(kUnknown, "Something bad happened");
  probe = false;
  SC_CHECK_EQ(TestReturnIfErrorCase(true, probe), status);
  SC_CHECK_FALSE(probe);
}

}  // namespace
}  // namespace wasm
}  // namespace sealed

int main() {
  sealed::wasm::TestDefaultStatus();
  sealed::wasm::TestStatusOkWithMessage();
  sealed::wasm::TestStatusUnknown();
  sealed::wasm::TestReturnIfError();
  fprintf(stderr, "PASSED\n");
  return 0;
}
