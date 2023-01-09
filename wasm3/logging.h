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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_LOGGING_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_LOGGING_H_

#include <string>

#include "third_party/sealedcomputing/wasm3/builtin/logging_wasm.h"

enum LogLevel {
  INFO = 0,
  WARNING = 1,
  ERROR = 2,
  FATAL = 3,  // This triggers a call to biPanic.
  DEBUG = 4,  // When serving, write to stderr, rather than sending a log RPC.
};

namespace sealed {
namespace wasm {

// Logger, e.g. SC_LOG(INFO) << "foo".
#define SC_LOG(level) sealed::wasm::Logger(level, __FILE__, __LINE__)

// Panic, with streaming message, e.g. SC_PANIC() << "Help!".
#define SC_PANIC() ::sealed::wasm::Logger(FATAL, __FILE__, __LINE__)

// Note: both CHECK and Check are already in the global namespace tests.  So,
// use SC_CHECK for "Sealed Computing Check".
#define SC_CHECK(assertion) \
  ::sealed::wasm::Checker((assertion), __FILE__, __LINE__, #assertion " ")

// This sends a logging RPC when destroyed, which happens on the same line when
// the constructor is called, but not assigned to a variable.
class Logger {
 public:
  Logger(LogLevel level, const std::string& filename, unsigned int line)
      : filename_(filename), level_(level), line_(line) {}
  ~Logger() { biSendLogRpc(level_, filename_.c_str(), line_, text_.c_str()); }
  Logger& operator<<(const char* s) {
    text_ += s;
    return *this;
  }
  Logger& operator<<(const std::string& s) {
    text_ += s;
    return *this;
  }

 private:
  std::string text_;
  const std::string& filename_;
  LogLevel level_;
  uint32_t line_;
};

#define SC_CHECK_FALSE(A) SC_CHECK(!(A))
#define SC_CHECK_EQ(A, B) SC_CHECK(A == B)
#define SC_CHECK_NE(A, B) SC_CHECK(A != B)
#define SC_CHECK_GE(A, B) SC_CHECK(A >= B)
#define SC_CHECK_GT(A, B) SC_CHECK(A > B)
#define SC_CHECK_LE(A, B) SC_CHECK(A <= B)
#define SC_CHECK_LT(A, B) SC_CHECK(A < B)
#define SC_CHECK_NOT_NULL(A) SC_CHECK(A != nullptr)
// Most OpenSSL calls returns one on success and 0 on failure.
#define SC_CHECK_SSL_OK(A) SC_CHECK_EQ(1, A)
// Some OpenSSL calls return negative values on failure.
#define SC_CHECK_SSL_NO_ERR(A) SC_CHECK_GE(A, 0)
// OpenSSL's AES calls don't follow the normal convention of other calls.
#define SC_CHECK_SSL_AES_OK(A) SC_CHECK_EQ(0, A)

// This calls rnPanic to reboot the interpreter if the condition is false.
class Checker {
 public:
  Checker(bool passed, const std::string& filename, unsigned int line,
          const std::string& assertion)
      : text_(assertion), filename_(filename), line_(line), failed_(!passed) {}
  ~Checker() {
    if (failed_) {
      biPanic(filename_.c_str(), line_, text_.c_str());
    }
  }
  Checker& operator<<(const char* s) {
    if (failed_) {
      text_ += s;
    }
    return *this;
  }
  Checker& operator<<(const std::string& s) {
    if (failed_) {
      text_ += s;
    }
    return *this;
  }

 private:
  std::string text_;
  const std::string& filename_;
  uint32_t line_;
  bool failed_;
};

}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_LOGGING_H_
