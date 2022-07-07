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

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string>
#include <tuple>
#include <type_traits>
#include <vector>

#include "base/logging.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/escaping.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/sealedcomputing/rpc/encode_decode.h"
#include "third_party/sealedcomputing/rpc/rpc.h"
#include "util/task/contrib/status_macros/return.h"
#include "util/task/status.h"
#include "util/task/status_macros.h"
#include "util/tuple/streamable.h"

namespace sealedcomputing::rpc {

namespace {

std::string U8ToString(const uint8_t* buffer, size_t length) {
  return std::string(reinterpret_cast<const char*>(buffer), length);
}

template <typename T>
void TestInputMatchesOutput(absl::string_view buffer, absl::string_view output,
                            T decoded_value) {
  CHECK_EQ(output, buffer) << "\ninput:  0x" << absl::BytesToHexString(buffer)
                           << "\noutput: 0x" << absl::BytesToHexString(output)
                           << "\ndecoded: "
                           << util::tuple::streamable(decoded_value);
}

void TestInputMatchesOutput(absl::string_view buffer,
                            absl::string_view output) {
  CHECK_EQ(output, buffer) << "\ninput:  0x" << absl::BytesToHexString(buffer)
                           << "\noutput: 0x" << absl::BytesToHexString(output);
}

template <typename T>
absl::Status DoT(absl::string_view buffer) {
  T decoded;
  {
    Decoder decoder;
    RETURN_IF_ERROR(decoder.StartDecoding(buffer));

    ASSIGN_OR_RETURN(decoded, decoder.Decode<T>());

    RETURN_IF_ERROR(decoder.FinishDecoding());
  }

  Encoder encoder;
  RETURN_IF_ERROR(encoder.StartEncoding());

  RETURN_IF_ERROR(encoder.Encode(decoded));

  ASSIGN_OR_RETURN(std::string encoded, encoder.FinishEncoding());
  TestInputMatchesOutput(buffer, encoded, decoded);

  return absl::OkStatus();
}

absl::Status DoU8(absl::string_view buffer) { return DoT<uint8_t>(buffer); }

absl::Status DoU16(absl::string_view buffer) { return DoT<uint16_t>(buffer); }

absl::Status DoU32(absl::string_view buffer) { return DoT<uint32_t>(buffer); }

absl::Status DoU64(absl::string_view buffer) { return DoT<uint64_t>(buffer); }

absl::Status DoU8Array(absl::string_view buffer) {
  return DoT<std::vector<uint8_t>>(buffer);
}

absl::Status DoStructure(absl::string_view buffer) {
  Decoder decoder;
  RETURN_IF_ERROR(decoder.StartDecoding(buffer));

  std::tuple<uint8_t, int8_t, uint16_t, int16_t, uint32_t, int32_t, uint64_t,
             int64_t, float_t, double_t>
      structure;
  ASSIGN_OR_RETURN(
      structure,
      (decoder.Decode<
          std::tuple<uint8_t, int8_t, uint16_t, int16_t, uint32_t, int32_t,
                     uint64_t, int64_t, float_t, double_t>>()));

  RETURN_IF_ERROR(decoder.FinishDecoding());

  Encoder encoder(true);
  CHECK_OK(encoder.Encode(structure));

  ASSIGN_OR_RETURN(std::string encoded_struct, encoder.FinishEncoding());

  TestInputMatchesOutput(buffer, encoded_struct);

  return absl::OkStatus();
}

absl::Status DoNestedArray(absl::string_view buffer) {
  return DoT<std::vector<std::vector<uint8_t>>>(buffer);
}

absl::Status DoAll(absl::string_view buffer) {
  if (buffer.length() == 0) {
    return absl::OkStatus();
  }

  switch (buffer[0]) {
    case 0:
      return DoT<uint8_t>(buffer.substr(1));
    case 1:
      return DoT<uint16_t>(buffer.substr(1));
    case 2:
      return DoT<uint32_t>(buffer.substr(1));
    case 3:
      return DoT<uint64_t>(buffer.substr(1));
    case 4:
      return DoT<int8_t>(buffer.substr(1));
    case 5:
      return DoT<int16_t>(buffer.substr(1));
    case 6:
      return DoT<int32_t>(buffer.substr(1));
    case 7:
      return DoT<int64_t>(buffer.substr(1));
    case 8:
      return DoT<std::vector<uint8_t>>(buffer.substr(1));
    case 9:
      return DoT<std::vector<uint16_t>>(buffer.substr(1));
    case 10:
      return DoT<std::vector<uint32_t>>(buffer.substr(1));
    case 11:
      return DoT<std::vector<uint64_t>>(buffer.substr(1));
    case 12:
      return DoT<std::vector<int8_t>>(buffer.substr(1));
    case 13:
      return DoT<std::vector<int16_t>>(buffer.substr(1));
    case 14:
      return DoT<std::vector<int32_t>>(buffer.substr(1));
    case 15:
      return DoT<std::vector<int64_t>>(buffer.substr(1));
    case 16:
      return DoT<std::string>(buffer.substr(1));
  }

  return absl::OkStatus();
}

template <typename T>
absl::Status DoEncodeDecode(const T& value) {
  std::string encoded;
  {
    Encoder encoder;
    RETURN_IF_ERROR(encoder.StartEncoding());
    RETURN_IF_ERROR(encoder.Encode(value));
    ASSIGN_OR_RETURN(std::string encoded, encoder.FinishEncoding());
  }

  T decoded;
  {
    Decoder decoder;
    RETURN_IF_ERROR(decoder.StartDecoding(encoded));
    ASSIGN_OR_RETURN(decoded, decoder.Decode<T>());
    RETURN_IF_ERROR(decoder.FinishDecoding());
  }
  CHECK_EQ(value, decoded);

  return absl::OkStatus();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* buffer, size_t length) {
  std::string input = U8ToString(buffer, length);
  DoAll(input).IgnoreError();
  DoStructure(input).IgnoreError();
  DoNestedArray(input).IgnoreError();
  DoEncodeDecode(input).IgnoreError();
  return 0;
}

}  // namespace

}  // namespace sealedcomputing::rpc
