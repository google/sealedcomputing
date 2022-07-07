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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_BYTESTRING_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_BYTESTRING_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "third_party/sealedcomputing/wasm3/statusor.h"

namespace sealed {
namespace wasm {

// A simple wrapper around an array of uint8_t that easily interoperates with
// - std::string
// - std::vector<uint8_t>
// - uint8_t arrays
// - c-style strings
// - (void*, size_t) pairs
// - (uint8_t*, size_t) pairs
class ByteString {
 public:
  // Creates a ByteString of `size` elements initilized to `value`.
  explicit ByteString(size_t size = 0, uint8_t value = 0);

  // Creates a ByteString of `size` bytes from `data`.
  ByteString(const void* data, size_t size);

  // Creates a ByteString from a c-style  string.
  // e.g. ByteString bytestring("ABCD");
  template <size_t N>
  ByteString(const char (&data)[N]) : ByteString(data, N - 1) {}

  // Creates a ByteString from an array of uint8_t.
  template <size_t N>
  ByteString(const uint8_t (&data)[N]) : ByteString(data, N) {}

  // Creates a ByteString from a std::string
  ByteString(const std::string& data);

  // Creates a ByteString from a std::vector<uint8_t>
  ByteString(const std::vector<uint8_t>& data);

  // Copy constructor.
  ByteString(const ByteString& other);

  // Move constructor
  ByteString(ByteString&& other);

  virtual ~ByteString();

  // Creates a ByteString an ASCII hex string.
  static StatusOr<ByteString> Hex(const std::string& data);

  template <size_t N>
  ByteString& operator=(const char (&data)[N]) {
    clear();
    size_ = N - 1;
    if (size_ == 0) {
      return *this;
    }
    data_ = new uint8_t[size_];
    for (size_t i = 0; i < size_; i++) {
      data_[i] = reinterpret_cast<const uint8_t*>(data)[i];
    }
    return *this;
  }

  template <size_t N>
  ByteString& operator=(const uint8_t (&data)[N]) {
    clear();
    size_ = N - 1;
    if (size_ == 0) {
      return *this;
    }
    data_ = new uint8_t[size_];
    for (size_t i = 0; i < size_; i++) {
      data_[i] = data[i];
    }
    return *this;
  }

  // Creates a new ByteString that is a copy of a subsequence.
  // If pos + len > size() then it truncates len to size() - pos.
  // If pos > size() then it returns an empty ByteString.
  ByteString substr(size_t pos = 0,
                    size_t len = static_cast<size_t>(-1ll)) const;

  ByteString& operator=(const std::string& data);
  ByteString& operator=(const std::vector<uint8_t>& data);
  ByteString& operator=(const ByteString& other);
  ByteString& operator=(ByteString&& other);

  size_t size() const { return size_; }
  bool empty() const { return size_ == 0; }
  void clear();
  explicit operator bool() const { return !empty(); }
  operator std::string() const { return string(); }
  operator std::vector<uint8_t>() const { return vector(); }
  explicit operator uint8_t*() { return data(); }
  explicit operator const uint8_t*() const { return data(); }

  uint8_t& operator[](size_t index) { return data_[index]; }
  uint8_t operator[](size_t index) const { return data_[index]; }
  uint8_t& at(size_t index) { return data_[index]; }
  uint8_t at(size_t index) const { return data_[index]; }

  uint8_t* data() { return data_; }
  const uint8_t* data() const { return data_; }

  std::vector<uint8_t> vector() const;
  std::string string() const;

  inline int compare(const void* data, size_t size) const;
  virtual int default_compare(const void* data, size_t size) const;

  // Returns 0 if the data is the same, neagative if "smaller", and
  // positive if "larger".
  // Note: Shorter strings are always "smaller". e.g. "Z" < "AA".
  int fast_compare(const void* data, size_t size) const;

  template <size_t N>
  int compare(const char (&data)[N]) const {
    if (N <= 1 || data == nullptr) {
      return size_ - (N - 1);
    }
    return default_compare(data, N - 1);
  }

  template <size_t N>
  int compare(const uint8_t (&data)[N]) const {
    if (N == 0 || data == nullptr) {
      return size_ - N;
    }
    return default_compare(data, N);
  }
  int compare(const ByteString& other) const;
  int compare(const std::string& other) const;
  int compare(const std::vector<uint8_t>& other) const;

  // Returns 0 if the data is the same, negative if "smaller", and
  // positive if "larger" with constant runtime.
  // This compares values in almost lexicographic order, but longer strings are
  // considered greater than shorter strings, e.g. "abc" < "defg".
  int constant_compare(const void* data, size_t size) const;
  int constant_compare(const ByteString& other) const;
  int constant_compare(const std::string& other) const;
  int constant_compare(const std::vector<uint8_t>& other) const;

  bool operator==(const ByteString& other) const;
  bool operator!=(const ByteString& other) const;
  bool operator==(const char* other) const;
  bool operator!=(const char* other) const;
  bool operator==(const std::string& other) const;
  bool operator!=(const std::string& other) const;
  bool operator==(const std::vector<uint8_t>& other) const;
  bool operator!=(const std::vector<uint8_t>& other) const;
  ByteString operator+(const ByteString& other) const;

  friend bool operator==(const std::string& str, const ByteString& btstr);
  friend bool operator!=(const std::string& str, const ByteString& btstr);
  friend bool operator==(const std::vector<uint8_t>& vtr,
                         const ByteString& btstr);
  friend bool operator!=(const std::vector<uint8_t>& vtr,
                         const ByteString& btstr);

  uint8_t* begin() { return data_; }
  uint8_t* end() { return data_ + size_; }
  const uint8_t* begin() const { return data_; }
  const uint8_t* end() const { return data_ + size_; }

  uint8_t* rbegin() { return data_ + size_ - 1; }
  uint8_t* rend() { return data_ - 1; }
  const uint8_t* rbegin() const { return data_ + size_ - 1; }
  const uint8_t* rend() const { return data_ - 1; }

  const uint8_t* cbegin() const { return data_; }
  const uint8_t* cend() const { return data_ + size_; }

  const uint8_t* crbegin() const { return data_ + size_ - 1; }
  const uint8_t* crend() const { return data_ - 1; }

  void swap(ByteString& other);

  // Converts data into an ASCII text string, returning a string of 2*size().
  std::string hex() const;
  virtual bool is_constant_time_compare() const { return false; }

 protected:
  ByteString& assign(const void* data, size_t size);
  // Optionally sanitize data.
  // Data is in an undefined state afterwards.
  virtual void clean_data() {}
  // Deallocate data and set size to 0.
  virtual void delete_data();
  size_t size_ = 0;
  uint8_t* data_ = nullptr;
};

template <size_t N>
bool operator==(const uint8_t (&data)[N], const ByteString& btstr) {
  return btstr.compare(data) == 0;
}

template <size_t N>
bool operator!=(const uint8_t (&data)[N], const ByteString& btstr) {
  return btstr.compare(data) != 0;
}

bool operator==(const std::string& str, const ByteString& btstr);
bool operator!=(const std::string& str, const ByteString& btstr);
bool operator==(const std::vector<uint8_t>& vtr, const ByteString& btstr);
bool operator!=(const std::vector<uint8_t>& vtr, const ByteString& btstr);

// A ByteString used to store secrets. It zeros the memory when it's deallocated
// and has constant time comparison.
class SecretByteString : public ByteString {
 public:
  // Use the same constructors as ByteString.
  using ByteString::ByteString;
  SecretByteString(const ByteString& data);
  ~SecretByteString() { clear(); }
  static StatusOr<SecretByteString> Hex(const std::string& data);

  // Use constant time comparison by default.
  int default_compare(const void* data, size_t size) const override;

  bool is_constant_time_compare() const override { return true; }

 protected:
  void clean_data() override;
};

}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_BYTESTRING_H_
