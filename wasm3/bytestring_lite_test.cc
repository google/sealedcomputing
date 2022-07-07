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
#include <memory>
#include <string>
#include <vector>

#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/logging.h"

namespace sealed {
namespace wasm {
namespace {

void ByteStringTestEmpty() {
  ByteString test;
  SC_CHECK(test.empty());
  // NOLINTBEGIN(readability-container-size-empty)
  SC_CHECK_EQ(test.size(), 0);
  SC_CHECK_EQ(test.data(), nullptr);
  SC_CHECK_EQ(test, "");
  SC_CHECK_EQ(test, std::string());
  SC_CHECK_EQ( test, std::vector<uint8_t>());
  // NOLINTEND(readability-container-size-empty)
  const uint8_t not_empty[1] = {0x10};
  SC_CHECK_NE(test, not_empty);

  ByteString test_null(not_empty, 0);
  SC_CHECK_EQ(test, test_null);
}

void ByteStringTestFromVectors() {
  ByteString test("\x55\x56\x57");
  uint8_t data[] = {0x55, 0x56, 0x57};
  std::vector<uint8_t> test_vector(data, data + sizeof(data));
  SC_CHECK_EQ(test, ByteString("\x55\x56\x57"));
  SC_CHECK_EQ(test, test_vector);
  SC_CHECK_EQ(test, ByteString(test_vector));
  ByteString test2 = test_vector;
  SC_CHECK_EQ(test, test2);
}

void ByteStringTestToVector() {
  ByteString test("\x55\x56\x57");
  uint8_t data[] = {0x55, 0x56, 0x57};
  std::vector<uint8_t> test_vector(data, data + sizeof(data));
  SC_CHECK_EQ(test.vector(), test_vector);
}

void ByteStringTestFromBytes() {
  uint8_t data1[] = {0x55, 0x56, 0x57};
  ByteString test(data1, 3);
  SC_CHECK_EQ(test, ByteString("\x55\x56\x57"));
  SC_CHECK_EQ(data1, test);
  SC_CHECK_EQ(test, data1);
  SC_CHECK_EQ(test, "\x55\x56\x57");
  SC_CHECK_EQ("\x55\x56\x57", test);

  test = "\x55\x56\x59";
  SC_CHECK_NE(test, "\x55\x56\x57");
  SC_CHECK_NE("\x55\x56\x57", test);
}

void ByteStringTestFromStrings() {
  ByteString test(std::string("\x55\x56\x57"));
  SC_CHECK_EQ(test, ByteString("\x55\x56\x57"));
  SC_CHECK_EQ(ByteString("\x55\x56\x57"), test);
  SC_CHECK_EQ(test, "\x55\x56\x57");
  SC_CHECK_EQ("\x55\x56\x57", test);

  test = "\x55\x56\x59";
  SC_CHECK_NE(test, "\x55\x56\x57");
  SC_CHECK_NE("\x55\x56\x57", test);
}

void ByteStringTestIterator() {
  ByteString test("\x55\x56\x57");
  for (uint8_t& byte : test) {
    byte++;
  }
  SC_CHECK_EQ(test, ByteString("\x56\x57\x58"));

  std::vector<uint8_t> backwards_vector;
  for (uint8_t* byte = test.rbegin(); byte != test.rend(); byte--) {
    backwards_vector.push_back(*byte);
  }
  SC_CHECK_EQ(backwards_vector, ByteString("\x58\x57\x56"));
}

void ByteStringTestCopyConstructor() {
  ByteString bs1("ABC123");
  ByteString bs2(bs1);
  SC_CHECK_EQ(bs1, bs2);
}

void ByteStringTestCopyOperator() {
  ByteString bs1("ABC123");
  ByteString bs2 = bs1;
  SC_CHECK_EQ(bs1, bs2);
}

bool truthyness(const ByteString& b) {
  if (b) {
    return true;
  } else {
    return false;
  }
}

size_t get_string_length(const std::string& str) { return str.size(); }

size_t get_vector_length(const std::vector<uint8_t>& vec) { return vec.size(); }

size_t get_bytestring_length(const ByteString& bytestr) {
  return bytestr.size();
}

int count(const uint8_t* data, size_t length, uint8_t value) {
  int count = 0;
  for (size_t i = 0; i < length; i++) {
    if (data[i] == value) {
      count++;
    }
  }
  return count;
}

void replace(uint8_t* data, size_t length, uint8_t value, uint8_t sub) {
  for (size_t i = 0; i < length; i++) {
    if (data[i] == value) {
      data[i] = sub;
    }
  }
}

void ByteStringTestConversionOperator() {
  ByteString empty;
  ByteString test("ABC123");
  std::string test_str("ABC123");
  uint8_t data[] = {'A', 'B', 'C', '1', '2', '3'};
  std::vector<uint8_t> test_vec(data, data + sizeof(data));

  SC_CHECK_FALSE(truthyness(empty));
  SC_CHECK(truthyness(test));

  SC_CHECK_EQ(get_string_length(test), 6);
  SC_CHECK_EQ(get_vector_length(test), 6);
  SC_CHECK_EQ(get_bytestring_length(test_str), 6);
  SC_CHECK_EQ(get_bytestring_length(test_vec), 6);
  SC_CHECK_EQ(count(test.operator const uint8_t*(), test.size(), 0x41), 1);
  SC_CHECK_EQ(count(static_cast<const uint8_t*>(test), test.size(), 0x41), 1);

  replace(test.operator uint8_t*(), test.size(), 0x41, 0x45);
  SC_CHECK_EQ(test, "EBC123");

  replace(static_cast<uint8_t*>(test), test.size(), 0x42, 0x46);
  SC_CHECK_EQ(test, "EFC123");
}

void ByteStringTestEquality() {
  ByteString test("\x56\x57\x58");
  SecretByteString clean_test("\x56\x57\x58");

  {
    ByteString test_copy(test);
    ByteString test_same("\x56\x57\x58");
    ByteString test_diff("\x56\x57\x58\x59");
    SC_CHECK_EQ(test, test);
    SC_CHECK_EQ(test, test_copy);
    SC_CHECK_EQ(test, test_same);
    SC_CHECK_NE(test, test_diff);
    SC_CHECK_EQ(test, test.substr());
    SC_CHECK_NE(test, test.substr(0, 1));
    SC_CHECK_NE(test, test.substr(1, 1));

    SC_CHECK_EQ(clean_test, clean_test);
    SC_CHECK_EQ(test, clean_test);
    SC_CHECK_EQ(clean_test, test);
    SC_CHECK_NE(clean_test, test_diff);
  }

  {
    uint8_t data_same[] = {0x56, 0x57, 0x58};
    uint8_t data_diff[] = {0x56, 0x57, 0x58, 0x59};
    SC_CHECK_EQ(test, data_same);
    SC_CHECK_NE(test, data_diff);
    SC_CHECK_EQ(data_same, test);
    SC_CHECK_NE(data_diff, test);

    SC_CHECK_EQ(clean_test, data_same);
    SC_CHECK_NE(clean_test, data_diff);
    SC_CHECK_EQ(data_same, clean_test);
    SC_CHECK_NE(data_diff, clean_test);
  }

  {
    std::string string_same("\x56\x57\x58");
    std::string string_diff("\x56\x57\x58\x59");
    SC_CHECK_EQ(test, string_same);
    SC_CHECK_NE(test, string_diff);
    SC_CHECK_EQ(string_same, test);
    SC_CHECK_NE(string_diff, test);

    SC_CHECK_EQ(clean_test, string_same);
    SC_CHECK_NE(clean_test, string_diff);
    SC_CHECK_EQ(string_same, clean_test);
    SC_CHECK_NE(string_diff, clean_test);
  }

  {
    uint8_t data1[] = {0x56, 0x57, 0x58};
    std::vector<uint8_t> vector_same(data1, data1 + sizeof(data1));
    uint8_t data2[] = {0x56, 0x57, 0x58, 0x59};
    std::vector<uint8_t> vector_diff(data2, data2 + sizeof(data2));
    SC_CHECK_EQ(test, vector_same);
    SC_CHECK_NE(test, vector_diff);
    SC_CHECK_EQ(vector_same, test);
    SC_CHECK_NE(vector_diff, test);

    SC_CHECK_EQ(clean_test, vector_same);
    SC_CHECK_NE(clean_test, vector_diff);
    SC_CHECK_EQ(vector_same, clean_test);
    SC_CHECK_NE(vector_diff, clean_test);
  }
}

void ByteStringTestComparison() {
  const size_t large_string_size = 0x7FFF;
  const size_t very_large_string_size = 0xFFFF;
  {
    ByteString five_a_s(5, 'a');
    ByteString six_a_s(6, 'a');
    ByteString five_b_s(5, 'b');
    ByteString six_b_s(6, 'b');

    SC_CHECK_LT(five_a_s.compare(five_b_s), 0);
    SC_CHECK_GT(five_b_s.compare(five_a_s), 0);
    SC_CHECK_LT(five_a_s.compare(six_a_s), 0);
    SC_CHECK_GT(six_a_s.compare(five_a_s), 0);
    SC_CHECK_LT(five_a_s.compare(six_b_s), 0);
    SC_CHECK_LT(five_b_s.compare(six_a_s), 0);

    SC_CHECK_LT(five_a_s.constant_compare(five_b_s), 0);
    SC_CHECK_GT(five_b_s.constant_compare(five_a_s), 0);
    SC_CHECK_LT(five_a_s.constant_compare(six_a_s), 0);
    SC_CHECK_GT(six_a_s.constant_compare(five_a_s), 0);
    SC_CHECK_LT(five_a_s.constant_compare(six_b_s), 0);
    SC_CHECK_GT(five_b_s.constant_compare(six_a_s), 0);
  }

  {
    ByteString long_bytestring(very_large_string_size, 'a');
    ByteString short_bytestring(1, 'b');

    SC_CHECK_GT(short_bytestring.constant_compare(long_bytestring), 0);
    SC_CHECK_LT(long_bytestring.constant_compare(short_bytestring), 0);
  }

  {
    ByteString test_1("ab");
    ByteString test_2("bc");

    // Check that "ab" > "a" when the byte following the single "a" is greater
    // than 'b'.
    SC_CHECK_GT(test_2.constant_compare(test_1.data(), 1), 0);
  }

  {
    ByteString long_bytestring(large_string_size, 'a');
    ByteString long_then_a = long_bytestring + "a";
    ByteString long_then_b = long_bytestring + "b";

    SC_CHECK_GT(long_then_b.constant_compare(long_then_a), 0);
    SC_CHECK_LT(long_then_a.constant_compare(long_then_b), 0);
  }

  {
    SecretByteString cleaning_five_c_s(5, 'c');
    SecretByteString cleaning_six_c_s(6, 'c');
    SecretByteString cleaning_five_d_s(5, 'd');
    SecretByteString cleaning_six_d_s(6, 'd');

    // Check that SecretByteString has the same behavior as constant_compare.
    SC_CHECK_LT(cleaning_five_c_s.compare(cleaning_six_d_s), 0);
    SC_CHECK_GT(cleaning_five_d_s.compare(cleaning_six_c_s), 0);
  }
}

void ByteStringTestHexOddLength() {
  SC_CHECK_FALSE(ByteString::Hex("A").ok());
  SC_CHECK_FALSE(ByteString::Hex("123").ok());
  SC_CHECK_FALSE(ByteString::Hex("abcde").ok());
}

void ByteStringTestHexBadDigits() {
  SC_CHECK_FALSE(ByteString::Hex("g123").ok());
  SC_CHECK_FALSE(ByteString::Hex("123G").ok());
  SC_CHECK_FALSE(ByteString::Hex(" 123").ok());
}

void ByteStringTestHexToBinExamples() {
  uint8_t data1[] = {0xde, 0xad, 0xbe, 0xef};
  ByteString expected1(data1, sizeof(data1));
  SC_CHECK_EQ(ByteString::Hex("DeadBeef"), expected1);
  char data2[] = {0x51, 0x42, 0x33, 0x24, 0x15};
  ByteString expected2(data2, sizeof(data2));
  std::string converted2;
  SC_CHECK_EQ(ByteString::Hex("5142332415"), expected2);
}

void ByteStringTestBinToHexExamples() {
  uint8_t data1[] = {0xde, 0xad, 0xbe, 0xef};
  std::string expected1("deadbeef");
  ByteString converted1 = ByteString(data1, sizeof(data1));
  SC_CHECK_EQ(expected1, converted1.hex());
  char data2[] = {0x51, 0x42, 0x33, 0x24, 0x15};
  std::string expected2("5142332415");
  ByteString converted2 = ByteString(data2, sizeof(data2));
  SC_CHECK_EQ(expected2, converted2.hex());
}

void ByteStringTestMoveOwnership() {
  {
    std::unique_ptr<ByteString> bs1 = std::make_unique<ByteString>("ABC123");
    const uint8_t* bs1_data = bs1->data();
    ByteString bs2(std::move(*bs1));
    SC_CHECK_EQ(bs1_data, bs2.data());
    SC_CHECK_EQ(bs2, "ABC123");
    SC_CHECK_NE(*bs1, "ABC123");  // NOLINT(bugprone-use-after-move)
    bs1.reset();
    SC_CHECK_EQ(bs2, "ABC123");
  }

  ByteString bs4;
  const uint8_t* bs3_data;
  {
    ByteString bs3("ABC123");
    bs3_data = bs3.data();
    bs4 = std::move(bs3);
  }
  SC_CHECK_EQ(bs3_data, bs4.data());
  SC_CHECK_EQ(bs4, "ABC123");
}

class TestSecretByteString : public SecretByteString {
 public:
  // Use the same constructors as SecretByteString.
  using SecretByteString::SecretByteString;
  ~TestSecretByteString() { clear(); }

 protected:
  void clean_data() override {
    SecretByteString::clean_data();
    for (size_t i = 0; i < size_; i++) {
      SC_CHECK_EQ(data_[i], 0);
    }
  }

  void delete_data() override {
    for (size_t i = 0; i < size_; i++) {
      SC_CHECK_EQ(data_[i], 0);
    }
    SecretByteString::delete_data();
  }
};

void SecretByteStringTestCheckCleansing() {
  TestSecretByteString clean("Secret Data");
}

void SecretByteStringTestSecretByteStringDereference() {
  TestSecretByteString clean(5);
  ByteString* ptr(&clean);
  *ptr = "hello";
  SC_CHECK_EQ(clean, "hello");
  SC_CHECK_EQ(*ptr, "hello");
  SC_CHECK_EQ(clean, *ptr);
}

void ByteStringTestHexAllOneByteStrings() {
  ByteString bin(1);
  for (uint32_t i = 0; i < UINT8_MAX; i++) {
    bin[0] = static_cast<char>(i);
    std::string hex = bin.hex();
    SC_CHECK_EQ(hex.size(), 2);
    auto res = ByteString::Hex(hex);
    SC_CHECK_OK(res);
    ByteString bin = *res;
    SC_CHECK_EQ(bin[0], i);
  }
}

}  // namespace
}  // namespace wasm
}  // namespace sealed

int main() {
  sealed::wasm::ByteStringTestEmpty();
  sealed::wasm::ByteStringTestFromVectors();
  sealed::wasm::ByteStringTestToVector();
  sealed::wasm::ByteStringTestFromBytes();
  sealed::wasm::ByteStringTestFromStrings();
  sealed::wasm::ByteStringTestIterator();
  sealed::wasm::ByteStringTestCopyConstructor();
  sealed::wasm::ByteStringTestCopyOperator();
  sealed::wasm::ByteStringTestConversionOperator();
  sealed::wasm::ByteStringTestEquality();
  sealed::wasm::ByteStringTestComparison();
  sealed::wasm::ByteStringTestHexOddLength();
  sealed::wasm::ByteStringTestHexBadDigits();
  sealed::wasm::ByteStringTestHexToBinExamples();
  sealed::wasm::ByteStringTestBinToHexExamples();
  sealed::wasm::ByteStringTestMoveOwnership();
  sealed::wasm::SecretByteStringTestCheckCleansing();
  sealed::wasm::SecretByteStringTestSecretByteStringDereference();
  sealed::wasm::ByteStringTestHexAllOneByteStrings();
  fprintf(stderr, "PASSED\n");
  return 0;
}
