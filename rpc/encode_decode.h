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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_RPC_ENCODE_DECODE_H_
#define THIRD_PARTY_SEALEDCOMPUTING_RPC_ENCODE_DECODE_H_

#include <string>
#include <tuple>
#include <type_traits>
#include <vector>

#include "base/logging.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/sealedcomputing/rpc/rpc.h"

namespace sealedcomputing::rpc {

template <typename T, typename... Ts>
auto head(const std::tuple<T, Ts...>& t) {
  return std::get<0>(t);
}

template <std::size_t... Ns, typename... Ts>
auto tail_impl(std::index_sequence<Ns...>, const std::tuple<Ts...>& t) {
  return std::make_tuple(std::get<Ns + 1u>(t)...);
}

template <typename... Ts>
auto tail(const std::tuple<Ts...>& t) {
  return tail_impl(std::make_index_sequence<sizeof...(Ts) - 1u>(), t);
}

template <typename T>
struct is_vector {
  static constexpr bool value = false;
};

template <template <typename...> class C, typename U>
struct is_vector<C<U>> {
  static constexpr bool value = std::is_same<C<U>, std::vector<U>>::value;
};

template <typename T>
struct is_tuple {
  static constexpr bool value = false;
};

template <template <typename...> class C, typename... U>
struct is_tuple<C<U...>> {
  static constexpr bool value = std::is_same<C<U...>, std::tuple<U...>>::value;
};

template <typename T>
struct is_string {
  static constexpr bool value = false;
};

template <template <typename...> class C, typename U>
struct is_string<C<U>> {
  static constexpr bool value = std::is_same<C<U>, std::basic_string<U>>::value;
};

// A C++ wrapper to encode an RPC.
class Encoder {
 public:
  Encoder(bool start = false) {
    if (start && !StartEncoding().ok()) {
      LOG(FATAL) << "StartEncoding failed";
    }
  }

  ~Encoder();

  absl::Status StartEncoding();

  absl::Status U8(uint8_t source_u8) { return Encode(source_u8); }

  absl::Status S8(int8_t source_s8) { return Encode(source_s8); }

  absl::Status U16(uint16_t source_u16) { return Encode(source_u16); }

  absl::Status S16(int16_t source_s16) { return Encode(source_s16); }

  absl::Status U32(uint32_t source_u32) { return Encode(source_u32); }

  absl::Status S32(int32_t source_s32) { return Encode(source_s32); }

  absl::Status U64(uint64_t source_u64) { return Encode(source_u64); }

  absl::Status S64(int64_t source_s64) { return Encode(source_s64); }

  absl::Status F32(float_t source_f32) { return Encode(source_f32); }

  absl::Status F64(double_t source_f64) { return Encode(source_f64); }

  template <typename T>
  std::enable_if_t<!is_vector<T>::value && !is_tuple<T>::value &&
                       !is_string<T>::value,
                   absl::Status>
  Encode(T source);

  template <typename T>
  std::enable_if_t<is_vector<T>::value && !is_tuple<T>::value, absl::Status>
  Encode(const T& source_array) {
    absl::Status status = StartArray(source_array.size());
    if (!status.ok()) {
      return status;
    }
    for (typename T::value_type source : source_array) {
      status = Encode<typename T::value_type>(source);
      if (!status.ok()) {
        return status;
      }
    }
    return FinishArray();
  }

  template <typename T>
  std::enable_if_t<!is_vector<T>::value && is_tuple<T>::value, absl::Status>
  Encode(const T& source_structure) {
    absl::Status status = StartStructure();
    if (!status.ok()) {
      return status;
    }
    status = EncodeStructHelper(source_structure);
    if (!status.ok()) {
      return status;
    }
    return FinishStructure();
  }

  template <typename T1, typename T2, typename... Ts>
  absl::Status Encode(T1 source_t1, T2 source_t2, Ts... source_ts) {
    absl::Status status = StartStructure();
    if (!status.ok()) {
      return status;
    }
    status =
        EncodeStructHelper(std::make_tuple(source_t1, source_t2, source_ts...));
    if (!status.ok()) {
      return status;
    }
    return FinishStructure();
  }

  template <typename T>
  std::enable_if_t<!is_vector<T>::value && !is_tuple<T>::value &&
                       is_string<T>::value,
                   absl::Status>
  Encode(const T& source_string) {
    return Encode(
        std::vector<uint8_t>(source_string.begin(), source_string.end()));
  }

  template <>
  absl::Status Encode(uint8_t source_u8);

  template <>
  absl::Status Encode(int8_t source_s8);

  template <>
  absl::Status Encode(uint16_t source_u16);

  template <>
  absl::Status Encode(int16_t source_s16);

  template <>
  absl::Status Encode(uint32_t source_u32);

  template <>
  absl::Status Encode(int32_t source_s32);

  template <>
  absl::Status Encode(uint64_t source_u64);

  template <>
  absl::Status Encode(int64_t source_s64);

  template <>
  absl::Status Encode(float_t source_f32);

  template <>
  absl::Status Encode(double_t source_f64);

  absl::Status StartArray(RpcLengthType array_count);

  absl::Status FinishArray();

  absl::Status StartStructure();

  absl::Status FinishStructure();

  absl::StatusOr<std::string> FinishEncoding();

 private:
  template <typename T>
  absl::Status EncodeStructHelper(const T& structure) {
    absl::Status status;
    if (std::tuple_size<T>::value >= 1) {
      status = Encode(head(structure));
      if (!status.ok()) {
        return status;
      }
    }
    if (std::tuple_size<T>::value >= 2) {
      status = EncodeStructHelper(tail(structure));
      if (!status.ok()) {
        return status;
      }
    }
    return absl::OkStatus();
  }

  template <>
  absl::Status EncodeStructHelper(const std::tuple<>& structure) {
    return absl::OkStatus();
  }

  RpcEncoderContext encoder_context_;
};

// A C++ wrapper to decode an RPC.
class Decoder {
 public:
  Decoder() : finished_(true) {}

  Decoder(absl::string_view buffer) : finished_(true) {
    if (!StartDecoding(buffer).ok()) {
      LOG(FATAL) << "StartDecoding failed";
    }
  }

  ~Decoder();

  absl::Status StartDecoding(absl::string_view buffer);

  absl::StatusOr<uint8_t> U8() { return Decode<uint8_t>(); }

  absl::StatusOr<int8_t> S8() { return Decode<int8_t>(); }

  absl::StatusOr<uint16_t> U16() { return Decode<uint16_t>(); }

  absl::StatusOr<int16_t> S16() { return Decode<int16_t>(); }

  absl::StatusOr<uint32_t> U32() { return Decode<uint32_t>(); }

  absl::StatusOr<int32_t> S32() { return Decode<int32_t>(); }

  absl::StatusOr<uint64_t> U64() { return Decode<uint64_t>(); }

  absl::StatusOr<int64_t> S64() { return Decode<int64_t>(); }

  absl::StatusOr<float_t> F32() { return Decode<float_t>(); }

  absl::StatusOr<double_t> F64() { return Decode<double_t>(); }

  template <typename T1, typename T2, typename... Ts>
  absl::StatusOr<std::tuple<T1, T2, Ts...>> Decode(
      std::tuple<T1, T2, Ts...> unused = std::tuple<T1, T2, Ts...>()) {
    absl::Status status = StartStructure();
    if (!status.ok()) {
      return status;
    }
    auto ret = DecodeHelper<T1, T2, Ts...>();
    status = FinishStructure();
    if (!status.ok()) {
      return status;
    }
    return ret;
  }

  template <typename T>
  std::enable_if_t<!is_vector<T>::value && !is_tuple<T>::value,
                   absl::StatusOr<T>>
  Decode(T unused = T());

  template <typename T>
  std::enable_if_t<is_vector<T>::value && !is_tuple<T>::value,
                   absl::StatusOr<T>>
  Decode(T unused = T()) {
    absl::StatusOr<RpcLengthType> decoded_length = StartArray();
    if (!decoded_length.ok()) {
      return decoded_length.status();
    }
    T array;
    for (RpcLengthType i = 0; i < *decoded_length; i++) {
      absl::StatusOr<typename T::value_type> decoded_t =
          Decode<typename T::value_type>();
      if (!decoded_t.ok()) {
        return decoded_t.status();
      }
      array.push_back(*decoded_t);
    }
    absl::Status status = FinishArray();
    if (!status.ok()) {
      return status;
    }
    return array;
  }

  template <typename T>
  std::enable_if_t<!is_vector<T>::value && is_tuple<T>::value,
                   absl::StatusOr<T>>
  Decode(const T& structure = T()) {
    absl::Status status = StartStructure();
    if (!status.ok()) {
      return status;
    }
    absl::StatusOr<T> ret = DecodeStructHelper(structure);
    if (!ret.ok()) {
      return ret.status();
    }
    status = FinishStructure();
    if (!status.ok()) {
      return status;
    }
    return ret;
  }

  template <typename T>
  std::enable_if_t<std::tuple_size_v<T> == 0, absl::StatusOr<T>>
  DecodeStructHelper(const T& structure = T()) {
    return std::tuple<>();
  }

  template <typename T>
  std::enable_if_t<std::tuple_size_v<T> == 1, absl::StatusOr<T>>
  DecodeStructHelper(const T& structure = T()) {
    auto ret_head = Decode(head(structure));
    if (!ret_head.ok()) {
      return ret_head.status();
    }
    return T(*ret_head);
  }

  template <typename T>
  std::enable_if_t<std::tuple_size_v<T> >= 2, absl::StatusOr<T>>
  DecodeStructHelper(const T& structure = T()) {
    auto ret_head = Decode(head(structure));
    if (!ret_head.ok()) {
      return ret_head.status();
    }

    auto ret_tail = Decode(tail(structure));
    if (!ret_tail.ok()) {
      return ret_tail.status();
    }

    return std::tuple_cat(std::tuple(*ret_head), *ret_tail);
  }

  template <>
  absl::StatusOr<uint8_t> Decode(uint8_t unused);

  template <>
  absl::StatusOr<int8_t> Decode(int8_t unused);

  template <>
  absl::StatusOr<uint16_t> Decode(uint16_t unused);

  template <>
  absl::StatusOr<int16_t> Decode(int16_t unused);

  template <>
  absl::StatusOr<uint32_t> Decode(uint32_t unused);

  template <>
  absl::StatusOr<int32_t> Decode(int32_t unused);

  template <>
  absl::StatusOr<uint64_t> Decode(uint64_t unused);

  template <>
  absl::StatusOr<int64_t> Decode(int64_t unused);

  template <>
  absl::StatusOr<float_t> Decode(float_t unused);

  template <>
  absl::StatusOr<double_t> Decode(double_t unused);

  template <>
  absl::StatusOr<std::string> Decode(std::string unused);

  absl::StatusOr<RpcLengthType> StartArray();

  absl::Status FinishArray();

  absl::Status StartStructure();

  absl::Status FinishStructure();

  absl::Status FinishDecoding();

 private:
  template <typename T1, typename T2, typename... Ts>
  absl::StatusOr<std::tuple<T1, T2, Ts...>> DecodeHelper(
      std::tuple<T1, T2, Ts...> unused = std::tuple<T1, T2, Ts...>()) {
    absl::StatusOr<T1> first = Decode<T1>();
    if (!first.ok()) {
      return first.status();
    }
    absl::StatusOr<std::tuple<T2, Ts...>> tail = Decode<T2, Ts...>();
    if (!tail.ok()) {
      return tail.status();
    }
    return std::tuple_cat(std::make_tuple(*first), *tail);
  }

  RpcDecoderContext decoder_context_;
  bool finished_;
};

}  // namespace sealedcomputing::rpc

#endif  // THIRD_PARTY_SEALEDCOMPUTING_RPC_ENCODE_DECODE_H_
