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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_STATUSOR_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_STATUSOR_H_

#include <utility>

#include "third_party/sealedcomputing/wasm3/builtin/logging_wasm.h"
#include "third_party/sealedcomputing/wasm3/logging.h"
#include "third_party/sealedcomputing/wasm3/status.h"

namespace sealed {
namespace wasm {

template <class T>
class StatusOr {
 public:
  explicit StatusOr() : data_(), status_(StatusCode::kUnknown, "") {}
  StatusOr(StatusCode error_code, const std::string& error_message)
      : status_(error_code, error_message) {}
  StatusOr(const Status& status) : status_(status) {}
  StatusOr(Status&& status) : status_(status) {}
  StatusOr(const T& data) : data_(data) {}
  StatusOr(T&& data) : data_(std::forward<T>(data)) {}
  StatusOr(const StatusOr&) = default;
  StatusOr(StatusOr&&) = default;

  StatusOr& operator=(const T& data) {
    data_ = data;
    status_ = Status();
    return *this;
  }
  StatusOr& operator=(T&& data) {
    data_ = std::forward<T>(data);
    status_ = Status();
    return *this;
  }
  StatusOr& operator=(const StatusOr&) = default;
  StatusOr& operator=(StatusOr&&) = default;
  operator bool() const { return ok(); }

  StatusCode code() const { return status_.code(); }
  const std::string& message() const { return status_.message(); }
  const Status& status() const { return status_; }

  bool ok() const { return status_.ok(); }

  T& value(T& other) {
    if (ok()) {
      return data_;
    }
    return other;
  }

  const T& value(const T& other) const& {
    if (ok()) {
      return data_;
    }
    return other;
  }

  T& operator*() & {
    SC_CHECK(ok());
    return data_;
  }

  const T& operator*() const& {
    SC_CHECK(ok());
    return data_;
  }

  T&& operator*() && {
    SC_CHECK(ok());
    return std::move(data_);
  }

  const T&& operator*() const&& {
    SC_CHECK(ok());
    return std::move(data_);
  }

  T* operator->() {
    SC_CHECK(ok());
    return &data_;
  }

  const T* operator->() const {
    SC_CHECK(ok());
    return &data_;
  }

 private:
  T data_;
  Status status_;
};

template <typename T>
Status& GetStatus(StatusOr<T>& status) {
  return status.status();
}

template <typename T>
const Status& GetStatus(const StatusOr<T>& status) {
  return status.status();
}

template <typename T>
bool operator==(const StatusOr<T>& lhs, const StatusOr<T>& rhs) {
  if (lhs.ok() && rhs.ok()) return *lhs == *rhs;
  return lhs.status() == rhs.status();
}

template <typename T>
bool operator!=(const StatusOr<T>& lhs, const StatusOr<T>& rhs) {
  return !(lhs == rhs);
}

template <typename T>
bool operator==(const StatusOr<T>& lhs, const T& rhs) {
  return *lhs == rhs;
}

template <typename T>
bool operator!=(const StatusOr<T>& lhs, const T& rhs) {
  return !(lhs == rhs);
}

template <typename T>
bool operator==(const T& lhs, const StatusOr<T>& rhs) {
  return lhs == *rhs;
}

template <typename T>
bool operator!=(const T& lhs, const StatusOr<T>& rhs) {
  return !(lhs == rhs);
}

template <typename T>
bool operator==(const StatusOr<T>& lhs, const Status& rhs) {
  return lhs.status() == rhs;
}

template <typename T>
bool operator!=(const StatusOr<T>& lhs, const Status& rhs) {
  return !(lhs == rhs);
}

template <typename T>
bool operator==(const Status& lhs, const StatusOr<T>& rhs) {
  return lhs == rhs.status();
}

template <typename T>
bool operator!=(const Status& lhs, const StatusOr<T>& rhs) {
  return !(lhs == rhs);
}

template <typename T>
bool operator==(const StatusOr<T>& lhs, StatusCode rhs) {
  return lhs.code() == rhs;
}

template <typename T>
bool operator!=(const StatusOr<T>& lhs, StatusCode rhs) {
  return !(lhs == rhs);
}

template <typename T>
bool operator==(StatusCode lhs, const StatusOr<T>& rhs) {
  return lhs == rhs.code();
}

template <typename T>
bool operator!=(StatusCode lhs, const StatusOr<T>& rhs) {
  return !(lhs == rhs);
}

// Evaluates `expr` that returns a `sealed::wasm::StatusOr<T>` object.
// If the contained status is non-OK, it is returned. Otherwse, the
// value of type `T` is moved into `lhs`.
#define SC_ASSIGN_OR_RETURN(lhs, expr) \
  SC_ASSIGN_OR_RETURN_IMPL_(SC_CONCAT_IMPL_(_statusor, __LINE__), lhs, expr)

#define SC_ASSIGN_OR_RETURN_IMPL_(statusor, lhs, expr) \
  auto statusor = (expr);                              \
  if (!statusor.ok()) {                                \
    return statusor.status();                          \
  }                                                    \
  lhs = std::move(*(statusor));

#define SC_ASSERT_OK_AND_ASSIGN(lhs, expr) \
  SC_ASSERT_OK_AND_ASSIGN_IMPL_(SC_CONCAT_IMPL_(_statusor, __LINE__), lhs, expr)

// For use in gUnit tests only.
#define SC_ASSERT_OK_AND_ASSIGN_IMPL_(statusor, lhs, expr)           \
  auto statusor = (expr);                                            \
  if (!statusor.ok()) {                                              \
    FAIL() << "Asserting OK StatusOr: Actual: " << statusor.status() \
           << " with message: " << statusor.message();               \
  }                                                                  \
  lhs = std::move(*(statusor));

#define SC_CONCAT_IMPL_INNER_(x, y) x##y
#define SC_CONCAT_IMPL_(x, y) SC_CONCAT_IMPL_INNER_(x, y)

#define SC_CHECK_OK_AND_ASSIGN(lhs, expr) lhs = std::move(*(expr));

}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_STATUSOR_H_
