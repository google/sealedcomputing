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

#include "third_party/sealedcomputing/wasm3/bytestring.h"

#include <cstdint>

#include "third_party/sealedcomputing/wasm3/status.h"

namespace sealed {
namespace wasm {
namespace {

// Convert a nibble (4 bits) to a hexadecimal character in constant time.
inline char nibbleToHex(char nibble) {
  const char mask = -(nibble < 10);
  return (mask & (nibble + '0')) | (~mask & (nibble - 10 + 'a'));
}

// Convert a hexadecimal digit to a nibble (4 bit int).  If |hex_digit| points
// to a valid hex digit, convert it to a nibble and return true.  Otherwise,
// return false; All in constant time.
inline bool hexToNibble(char* hex_digit) {
  const char mask_1 = -((*hex_digit >= '0') & (*hex_digit <= '9'));
  const char mask_2 = -((*hex_digit >= 'a') & (*hex_digit <= 'f'));
  const char mask_3 = -((*hex_digit >= 'A') & (*hex_digit <= 'F'));

  *hex_digit -= (mask_1 & '0') | (mask_2 & ('a' - 10)) | (mask_3 & ('A' - 10));
  return (mask_1 | mask_2 | mask_3) != 0;
}

// Constant time conversion from a ByteString to a hexadecimal std::string.
std::string BinToHex(const ByteString& binary_string) {
  size_t len = binary_string.size();
  std::string result(len << 1, '\0');
  size_t i = 0;
  for (char c : binary_string) {
    result[i++] = nibbleToHex((c >> 4) & 0xf);
    result[i++] = nibbleToHex(c & 0xf);
  }
  return result;
}

// Constant time conversion from a hexadecimal std::string to ByteString.
// Leaks length and if the string was a valid hex string.
StatusOr<ByteString> HexToBin(const std::string& hex_string) {
  size_t len = hex_string.size();
  if (len & 1) {
    return Status(kInvalidArgument,
                  "Hex strings must have an even number of characters");
  }
  len >>= 1;
  ByteString binary_string(len);
  size_t j = 0;
  bool result = true;
  for (size_t i = 0; i < len; i++) {
    char hi = hex_string[j++];
    char low = hex_string[j++];
    result &= hexToNibble(&hi) && hexToNibble(&low);
    binary_string[i] = (hi << 4) | low;
  }
  Status invalid(kInvalidArgument, "Hex string has an invalid hex digit");
  if (!result) {
    return invalid;
  }
  return binary_string;
}

}  // namespace

ByteString::ByteString(size_t size, uint8_t value)
    : size_(size), data_(new uint8_t[size_]) {
  for (size_t i = 0; i < size_; i++) {
    data_[i] = value;
  }
  if (size_ == 0) {
    clear();
  }
}

ByteString::ByteString(const void* data, size_t size)
    : size_(size), data_(new uint8_t[size_]) {
  for (size_t i = 0; i < size_; i++) {
    data_[i] = static_cast<const uint8_t*>(data)[i];
  }
  if (size_ == 0) {
    clear();
  }
}

ByteString::ByteString(const std::string& data)
    : ByteString(data.data(), data.size()) {}

ByteString::ByteString(const std::vector<uint8_t>& data)
    : ByteString(data.data(), data.size()) {}

ByteString::ByteString(const ByteString& other)
    : ByteString(other.data(), other.size()) {}

ByteString::ByteString(ByteString&& other)
    : size_(other.size_), data_(other.data_) {
  other.data_ = nullptr;
  other.size_ = 0;
}

ByteString::~ByteString() { clear(); }

StatusOr<ByteString> ByteString::Hex(const std::string& data) {
  return HexToBin(data);
}

ByteString& ByteString::assign(const void* data, size_t size) {
  clear();
  if (size != 0) {
    size_ = size;
    data_ = new uint8_t[size_];
    for (size_t i = 0; i < size_; i++) {
      data_[i] = static_cast<const uint8_t*>(data)[i];
    }
  }
  return *this;
}

ByteString& ByteString::operator=(const std::string& data) {
  assign(data.data(), data.size());
  return *this;
}

ByteString& ByteString::operator=(const std::vector<uint8_t>& data) {
  assign(data.data(), data.size());
  return *this;
}

ByteString& ByteString::operator=(const ByteString& other) {
  if (this == &other) {
    return *this;
  }
  assign(other.data(), other.size());
  return *this;
}

ByteString& ByteString::operator=(ByteString&& other) {
  if (this != &other) {
    clear();
    data_ = other.data_;
    size_ = other.size_;
    other.data_ = nullptr;
    other.size_ = 0;
  }
  return *this;
}

void ByteString::clear() {
  clean_data();
  delete_data();
}

ByteString ByteString::substr(size_t pos, size_t len) const {
  // Note: be careful about checking for overflow.
  if (pos > size()) {
    return ByteString();
  }
  // Truncate len if it is too long.
  // Note: `pos + len < pos` is only true iff `pos + len` overflow size_t.
  if (len == static_cast<size_t>(-1ll) || pos + len > size() ||
      pos + len < pos) {
    len = size_ - pos;
  }
  return ByteString(data_ + pos, len);
}

std::vector<uint8_t> ByteString::vector() const {
  return std::vector<uint8_t>(data_, data_ + size_);
}

std::string ByteString::string() const {
  return std::string(reinterpret_cast<const char*>(data_), size_);
}

inline int ByteString::compare(const void* data, size_t size) const {
  return default_compare(data, size);
}

int ByteString::default_compare(const void* data, size_t size) const {
  return fast_compare(data, size);
}

int ByteString::fast_compare(const void* data, size_t size) const {
  if (size_ != size) {
    return size_ - size;
  }
  if (data == data_) {
    return 0;
  }
  const uint8_t* value = static_cast<const uint8_t*>(data);
  for (size_t i = 0; i < size_; i++) {
    if (data_[i] != value[i]) {
      return data_[i] - value[i];
    }
  }
  return 0;
}

int ByteString::compare(const ByteString& other) const {
  return default_compare(other.data_, other.size_);
}

int ByteString::compare(const std::string& other) const {
  return default_compare(other.data(), other.size());
}

int ByteString::compare(const std::vector<uint8_t>& other) const {
  return default_compare(other.data(), other.size());
}

// An implementaion of a constant-time ternary operator.
// If `cmp` == 1 return `if_true`,
// if `cmp` == 0 return `if_false`,
// undefined otherwise.
static inline int64_t constant_ternary(bool cmp, int64_t if_true,
                                       int64_t if_false) {
  return (-cmp & if_true) ^ (~-cmp & if_false);
}

// Returns +1 if `val` > 0, -1 if `val` < 0 and 0 if 'val` == 0.
static inline int constant_signum(int64_t val) { return (0 < val) - (val < 0); }

int ByteString::constant_compare(const void* data, size_t size) const {
  const uint8_t* value = static_cast<const uint8_t*>(data);
  size_t min_size = constant_ternary(size_ < size, size_, size);
  int64_t result = 0;
  for (size_t i = 0; i < min_size; i++) {
    result = constant_ternary(result == 0, data_[i] - value[i], result);
  }
  result = constant_ternary(result == 0, size_ - size, result);
  return constant_signum(result);
}

int ByteString::constant_compare(const ByteString& other) const {
  return constant_compare(other.data_, other.size_);
}

int ByteString::constant_compare(const std::string& other) const {
  return constant_compare(other.data(), other.size());
}

int ByteString::constant_compare(const std::vector<uint8_t>& other) const {
  return constant_compare(other.data(), other.size());
}

bool ByteString::operator==(const ByteString& other) const {
  if (other.is_constant_time_compare()) {
    return other.compare(*this) == 0;
  }
  return compare(other) == 0;
}

bool ByteString::operator!=(const ByteString& other) const {
  if (other.is_constant_time_compare()) {
    return other.compare(*this) != 0;
  }
  return compare(other) != 0;
}

bool ByteString::operator==(const char* other) const {
  return compare(other) == 0;
}

bool ByteString::operator!=(const char* other) const {
  return compare(other) != 0;
}

bool ByteString::operator==(const std::string& other) const {
  return compare(other) == 0;
}

bool ByteString::operator!=(const std::string& other) const {
  return compare(other) != 0;
}

bool ByteString::operator==(const std::vector<uint8_t>& other) const {
  return compare(other) == 0;
}

bool ByteString::operator!=(const std::vector<uint8_t>& other) const {
  return compare(other) != 0;
}

void ByteString::swap(ByteString& other) {
  if (this != &other) {
    size_t tmp_size = size_;
    uint8_t* tmp_data = data_;
    size_ = other.size_;
    data_ = other.data_;
    other.size_ = tmp_size;
    other.data_ = tmp_data;
  }
}

std::string ByteString::hex() const { return BinToHex(string()); }

void ByteString::delete_data() {
  if (data_ != nullptr) {
    delete[] data_;
  }
  size_ = 0;
  data_ = nullptr;
}

bool operator==(const std::string& str, const ByteString& btstr) {
  return btstr.compare(str) == 0;
}

bool operator!=(const std::string& str, const ByteString& btstr) {
  return btstr.compare(str) != 0;
}

bool operator==(const std::vector<uint8_t>& vtr, const ByteString& btstr) {
  return btstr.compare(vtr) == 0;
}

bool operator!=(const std::vector<uint8_t>& vtr, const ByteString& btstr) {
  return btstr.compare(vtr) != 0;
}

SecretByteString::SecretByteString(const ByteString& data)
    : SecretByteString(data.data(), data.size()) {}

StatusOr<SecretByteString> SecretByteString::Hex(const std::string& data) {
  SC_ASSIGN_OR_RETURN(SecretByteString ret, HexToBin(data));
  return ret;
}

void SecretByteString::clean_data() {
  if (data_ != nullptr) {
    volatile uint8_t* p = data_;
    for (size_t i = 0; i < size_; i++) {
      p[i] = 0;
    }
  }
}

int SecretByteString::default_compare(const void* data, size_t size) const {
  return constant_compare(data, size);
}

ByteString ByteString::operator+(const ByteString& other) const {
  ByteString result(this->size() + other.size());
  memcpy(result.data_, this->data(), this->size());
  memcpy(result.data_ + this->size(), other.data(), other.size());
  return result;
}

}  // namespace wasm
}  // namespace sealed
