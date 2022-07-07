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

#include "third_party/sealedcomputing/rpc/encode_decode.h"

#include <vector>

namespace sealedcomputing::rpc {

Encoder::~Encoder() {
  if (!rpcFreeEncoderContext(&encoder_context_)) {
    LOG(FATAL) << "rpcDestroyEncoderContext failed";
  }
}

absl::Status Encoder::StartEncoding() {
  if (!rpcInitEncoderContext(&encoder_context_, true)) {
    return absl::ResourceExhaustedError("Failed to allocate memory");
  }
  return absl::OkStatus();
}

template <typename T>
std::enable_if_t<!is_vector<T>::value && !is_tuple<T>::value &&
                     !is_string<T>::value,
                 absl::Status>
Encoder::Encode(T source) {
  return absl::FailedPreconditionError("Unsupported type");
}

template <>
absl::Status Encoder::Encode(uint8_t source_u8) {
  if (!rpcEncodeU8(&encoder_context_, source_u8)) {
    return absl::UnknownError("Error in rpcEncodeU8");
  }
  return absl::OkStatus();
}

template <>
absl::Status Encoder::Encode(int8_t source_s8) {
  if (!rpcEncodeS8(&encoder_context_, source_s8)) {
    return absl::UnknownError("Error in rpcEncodeS8");
  }
  return absl::OkStatus();
}

template <>
absl::Status Encoder::Encode(uint16_t source_u16) {
  if (!rpcEncodeU16(&encoder_context_, source_u16)) {
    return absl::UnknownError("Error in rpcEncodeU16");
  }
  return absl::OkStatus();
}

template <>
absl::Status Encoder::Encode(int16_t source_s16) {
  if (!rpcEncodeS16(&encoder_context_, source_s16)) {
    return absl::UnknownError("Error in rpcEncodeS16");
  }
  return absl::OkStatus();
}

template <>
absl::Status Encoder::Encode(uint32_t source_u32) {
  if (!rpcEncodeU32(&encoder_context_, source_u32)) {
    return absl::UnknownError("Error in rpcEncodeU32");
  }
  return absl::OkStatus();
}

template <>
absl::Status Encoder::Encode(int32_t source_s32) {
  if (!rpcEncodeS32(&encoder_context_, source_s32)) {
    return absl::UnknownError("Error in rpcEncodeS32");
  }
  return absl::OkStatus();
}

template <>
absl::Status Encoder::Encode(uint64_t source_u64) {
  if (!rpcEncodeU64(&encoder_context_, source_u64)) {
    return absl::UnknownError("Error in rpcEncodeU64");
  }
  return absl::OkStatus();
}

template <>
absl::Status Encoder::Encode(int64_t source_s64) {
  if (!rpcEncodeS64(&encoder_context_, source_s64)) {
    return absl::UnknownError("Error in rpcEncodeS64");
  }
  return absl::OkStatus();
}

template <>
absl::Status Encoder::Encode(float_t source_f32) {
  if (!rpcEncodeF32(&encoder_context_, source_f32)) {
    return absl::UnknownError("Error in rpcEncodeF32");
  }
  return absl::OkStatus();
}

template <>
absl::Status Encoder::Encode(double_t source_f64) {
  if (!rpcEncodeF64(&encoder_context_, source_f64)) {
    return absl::UnknownError("Error in rpcEncodeF64");
  }
  return absl::OkStatus();
}

absl::Status Encoder::StartArray(RpcLengthType array_count) {
  if (!rpcEncodeStartArray(&encoder_context_, array_count)) {
    return absl::UnknownError("Error in rpcEncodeStartArray");
  }
  return absl::OkStatus();
}

absl::Status Encoder::FinishArray() {
  if (!rpcEncodeFinishArray(&encoder_context_)) {
    return absl::UnknownError("Error in rpcEncodeFinishArray");
  }
  return absl::OkStatus();
}

absl::Status Encoder::StartStructure() {
  if (!rpcEncodeStartStructure(&encoder_context_)) {
    return absl::UnknownError("Error in rpcEncodeStartStructure");
  }
  return absl::OkStatus();
}

absl::Status Encoder::FinishStructure() {
  if (!rpcEncodeFinishStructure(&encoder_context_)) {
    return absl::UnknownError("Error in rpcEncodeFinishStructure");
  }
  return absl::OkStatus();
}

absl::StatusOr<std::string> Encoder::FinishEncoding() {
  uint8_t* buffer;
  RpcLengthType length;
  if (!rpcFinishEncoding(&encoder_context_, &buffer, &length)) {
    return absl::UnknownError("Error in rpcFinishEncoding");
  }
  return std::string(reinterpret_cast<const char*>(buffer), length);
}

//  ******************************************************
//  Decode
//  ******************************************************

Decoder::~Decoder() {
  if (!finished_) {
    FinishDecoding().IgnoreError();
  }
}

absl::Status Decoder::StartDecoding(absl::string_view buffer) {
  finished_ = false;
  if (!rpcInitDecoderContext(&decoder_context_, true, (void*)buffer.data(),
                             buffer.length())) {
    finished_ = true;
    return absl::InvalidArgumentError("Invalid buffer");
  }
  return absl::OkStatus();
}

template <typename T>
std::enable_if_t<!is_vector<T>::value && !is_tuple<T>::value, absl::StatusOr<T>>
Decoder::Decode(T unused) {
  return absl::FailedPreconditionError("Unsupported type");
}

template <>
absl::StatusOr<uint8_t> Decoder::Decode(uint8_t unused) {
  if (finished_) {
    return absl::FailedPreconditionError("No buffer provided");
  }
  uint8_t decoded_u8;
  if (rpcDecodeU8(&decoder_context_, &decoded_u8)) {
    return decoded_u8;
  }
  return absl::OutOfRangeError("Exceeded buffer bounds");
}

template <>
absl::StatusOr<int8_t> Decoder::Decode(int8_t unused) {
  if (finished_) {
    return absl::FailedPreconditionError("No buffer provided");
  }
  int8_t decoded_s8;
  if (rpcDecodeS8(&decoder_context_, &decoded_s8)) {
    return decoded_s8;
  }
  return absl::OutOfRangeError("Exceeded buffer bounds");
}

template <>
absl::StatusOr<uint16_t> Decoder::Decode(uint16_t unused) {
  if (finished_) {
    return absl::FailedPreconditionError("No buffer provided");
  }
  uint16_t decoded_u16;
  if (rpcDecodeU16(&decoder_context_, &decoded_u16)) {
    return decoded_u16;
  }
  return absl::OutOfRangeError("Exceeded buffer bounds");
}

template <>
absl::StatusOr<int16_t> Decoder::Decode(int16_t unused) {
  if (finished_) {
    return absl::FailedPreconditionError("No buffer provided");
  }
  int16_t decoded_s16;
  if (rpcDecodeS16(&decoder_context_, &decoded_s16)) {
    return decoded_s16;
  }
  return absl::OutOfRangeError("Exceeded buffer bounds");
}

template <>
absl::StatusOr<uint32_t> Decoder::Decode(uint32_t unused) {
  if (finished_) {
    return absl::FailedPreconditionError("No buffer provided");
  }
  uint32_t decoded_u32;
  if (rpcDecodeU32(&decoder_context_, &decoded_u32)) {
    return decoded_u32;
  }
  return absl::OutOfRangeError("Exceeded buffer bounds");
}

template <>
absl::StatusOr<int32_t> Decoder::Decode(int32_t unused) {
  if (finished_) {
    return absl::FailedPreconditionError("No buffer provided");
  }
  int32_t decoded_s32;
  if (rpcDecodeS32(&decoder_context_, &decoded_s32)) {
    return decoded_s32;
  }
  return absl::OutOfRangeError("Exceeded buffer bounds");
}

template <>
absl::StatusOr<uint64_t> Decoder::Decode(uint64_t unused) {
  if (finished_) {
    return absl::FailedPreconditionError("No buffer provided");
  }
  uint64_t decoded_u64;
  if (rpcDecodeU64(&decoder_context_, &decoded_u64)) {
    return decoded_u64;
  }
  return absl::OutOfRangeError("Exceeded buffer bounds");
}

template <>
absl::StatusOr<int64_t> Decoder::Decode(int64_t unused) {
  if (finished_) {
    return absl::FailedPreconditionError("No buffer provided");
  }
  int64_t decoded_s64;
  if (rpcDecodeS64(&decoder_context_, &decoded_s64)) {
    return decoded_s64;
  }
  return absl::OutOfRangeError("Exceeded buffer bounds");
}

template <>
absl::StatusOr<float_t> Decoder::Decode(float_t unused) {
  if (finished_) {
    return absl::FailedPreconditionError("No buffer provided");
  }
  float_t decoded_f32;
  if (rpcDecodeF32(&decoder_context_, &decoded_f32)) {
    return decoded_f32;
  }
  return absl::OutOfRangeError("Exceeded buffer bounds");
}

template <>
absl::StatusOr<double_t> Decoder::Decode(double_t unused) {
  if (finished_) {
    return absl::FailedPreconditionError("No buffer provided");
  }
  double_t decoded_f64;
  if (rpcDecodeF64(&decoder_context_, &decoded_f64)) {
    return decoded_f64;
  }
  return absl::OutOfRangeError("Exceeded buffer bounds");
}

template <>
absl::StatusOr<std::string> Decoder::Decode(std::string unused) {
  absl::StatusOr<std::vector<uint8_t>> ret = Decode<std::vector<uint8_t>>();
  if (!ret.ok()) {
    return ret.status();
  }
  return std::string(ret->begin(), ret->end());
}

absl::StatusOr<RpcLengthType> Decoder::StartArray() {
  if (finished_) {
    return absl::FailedPreconditionError("No buffer provided");
  }
  RpcLengthType decoded_length;
  if (!rpcDecodeStartArray(&decoder_context_, &decoded_length)) {
    return absl::OutOfRangeError("Exceeded buffer bounds");
  }
  return decoded_length;
}

absl::Status Decoder::FinishArray() {
  if (finished_) {
    return absl::FailedPreconditionError("No buffer provided");
  }
  if (!rpcDecodeFinishArray(&decoder_context_)) {
    return absl::UnknownError("Error in rpcDecodeFinishArray");
  }
  return absl::OkStatus();
}

absl::Status Decoder::StartStructure() {
  if (finished_) {
    return absl::FailedPreconditionError("No buffer provided");
  }
  if (!rpcDecodeStartStructure(&decoder_context_)) {
    return absl::UnknownError("Error in rpcDecodeStartStructure");
  }
  return absl::OkStatus();
}

absl::Status Decoder::FinishStructure() {
  if (finished_) {
    return absl::FailedPreconditionError("No buffer provided");
  }
  if (!rpcDecodeFinishStructure(&decoder_context_)) {
    return absl::UnknownError("Error in rpcDecodeFinishStructure");
  }
  return absl::OkStatus();
}

absl::Status Decoder::FinishDecoding() {
  if (!finished_) {
    if (!rpcFinishDecoding(&decoder_context_)) {
      rpcFreeDecoderContext(&decoder_context_);
      finished_ = true;
      return absl::FailedPreconditionError("Buffer not fully consumed");
    }
    if (!rpcFreeDecoderContext(&decoder_context_)) {
      return absl::FailedPreconditionError("Decoder failed to be destroyed");
    }
    finished_ = true;
  }
  return absl::OkStatus();
}

}  // namespace sealedcomputing::rpc
