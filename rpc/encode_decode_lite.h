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

// This header is meant to be used inside sealed applications that have no
// access to google3 libraries and must stand alone.  Since only generated code
// accesses this functionality, emphasis is on speed and simplicity rather than
// usability.

#ifndef THIRD_PARTY_SEALEDCOMPUTING_RPC_ENCODE_DECODE_LITE_H_
#define THIRD_PARTY_SEALEDCOMPUTING_RPC_ENCODE_DECODE_LITE_H_

#include <string>
#include <vector>

#include "third_party/sealedcomputing/rpc/rpc.h"
#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/logging.h"

namespace sealed {
namespace rpc {

// Limit requests to 16MiB in size.
constexpr size_t kMaxRpcSize = 1 << 24;

// A C++ wrapper to encode an RPC.
class Encoder {
 public:
  // NOTE: if encoding secret data, set compress_ints to false.  Otherwise the
  // compressed size will leak information about the value of integers, and will
  // not be constant-time.
  Encoder(bool compress_ints = true) {
    rpcInitEncoderContext(&ctx_, compress_ints);
  }
  ~Encoder() { rpcFreeEncoderContext(&ctx_); }
  std::string Finish() {
    uint8_t *ret_buffer;
    RpcLengthType length;
    SC_CHECK(rpcFinishEncoding(&ctx_, &ret_buffer, &length));
    return std::string(reinterpret_cast<char *>(ret_buffer), length);
  }
  void U8(uint8_t source_u8) { SC_CHECK(rpcEncodeU8(&ctx_, source_u8)); }
  void S8(int8_t source_s8) { SC_CHECK(rpcEncodeS8(&ctx_, source_s8)); }
  void U16(uint16_t source_u16) { SC_CHECK(rpcEncodeU16(&ctx_, source_u16)); }
  void S16(int16_t source_s16) { SC_CHECK(rpcEncodeS16(&ctx_, source_s16)); }
  void U32(uint32_t source_u32) { SC_CHECK(rpcEncodeU32(&ctx_, source_u32)); }
  void S32(int32_t source_s32) { SC_CHECK(rpcEncodeS32(&ctx_, source_s32)); }
  void U64(uint64_t source_u64) { SC_CHECK(rpcEncodeU64(&ctx_, source_u64)); }
  void S64(int64_t source_s64) { SC_CHECK(rpcEncodeS64(&ctx_, source_s64)); }
  void F32(float source_f32) { SC_CHECK(rpcEncodeF32(&ctx_, source_f32)); }
  void F64(double source_f64) { SC_CHECK(rpcEncodeF64(&ctx_, source_f64)); }
  void Bool(bool value) { U8(static_cast<uint8_t>(value)); }
  void String(const std::string &s) {
    static_assert(sizeof(char) == 1 && sizeof(int8_t) == 1,
                  "Characters and int8_t must have size 1 to run this code.");
    SC_CHECK(rpcEncodeStartArray(&ctx_, s.size()));
    for (auto c : s) {
      SC_CHECK(rpcEncodeS8(&ctx_, static_cast<int8_t>(c)));
    }
    SC_CHECK(rpcEncodeFinishArray(&ctx_));
  }
  void StartArray(RpcLengthType len) {
    SC_CHECK(rpcEncodeStartArray(&ctx_, len));
  }
  void FinishArray() { SC_CHECK(rpcEncodeFinishArray(&ctx_)); }
  void StartStruct() { SC_CHECK(rpcEncodeStartStructure(&ctx_)); }
  void FinishStruct() { SC_CHECK(rpcEncodeFinishStructure(&ctx_)); }

 private:
  RpcEncoderContext ctx_;
};

// A C++ wrapper to decode an RPC.
class Decoder {
 public:
  Decoder(const std::string &buffer, bool compress_ints = true)
      : buffer_(buffer) {
    rpcInitDecoderContext(&ctx_, compress_ints, buffer_.data(), buffer.size());
  }
  Decoder(const wasm::ByteString &buffer, bool compress_ints = true)
      : buffer_(buffer.string()) {
    rpcInitDecoderContext(&ctx_, compress_ints, buffer.data(), buffer_.size());
  }
  ~Decoder() { SC_CHECK(rpcFreeDecoderContext(&ctx_)); }
  bool Finish() { return rpcFinishDecoding(&ctx_); }
  bool U8(uint8_t *val) { return rpcDecodeU8(&ctx_, val); }
  bool S8(int8_t *val) { return rpcDecodeS8(&ctx_, val); }
  bool U16(uint16_t *val) { return rpcDecodeU16(&ctx_, val); }
  bool S16(int16_t *val) { return rpcDecodeS16(&ctx_, val); }
  bool U32(uint32_t *val) { return rpcDecodeU32(&ctx_, val); }
  bool S32(int32_t *val) { return rpcDecodeS32(&ctx_, val); }
  bool U64(uint64_t *val) { return rpcDecodeU64(&ctx_, val); }
  bool S64(int64_t *val) { return rpcDecodeS64(&ctx_, val); }
  bool F32(float *val) { return rpcDecodeF32(&ctx_, val); }
  bool F64(double *val) { return rpcDecodeF64(&ctx_, val); }
  bool Bool(bool *value) {
    uint8_t v;
    if (!U8(&v)) {
      return false;
    }
    *value = static_cast<bool>(v);
    return true;
  }
  bool String(std::string *s) {
    RpcLengthType length;
    if (!rpcDecodeStartArray(&ctx_, &length) || length > kMaxRpcSize) {
      return false;
    }
    s->resize(length);
    for (RpcLengthType i = 0; i < length; i++) {
      int8_t c;
      if (!rpcDecodeS8(&ctx_, &c)) {
        return false;
      }
      (*s)[i] = c;
    }
    return rpcDecodeFinishArray(&ctx_);
  }
  bool StartArray(RpcLengthType *len) {
    return rpcDecodeStartArray(&ctx_, len);
  }
  bool FinishArray() { return rpcDecodeFinishArray(&ctx_); }
  bool StartStruct() { return rpcDecodeStartStructure(&ctx_); }
  bool FinishStruct() { return rpcDecodeFinishStructure(&ctx_); }

 private:
  RpcDecoderContext ctx_;
  // Copy it because auto-conversions to std::string cause memory corruption
  std::string buffer_;
};

}  // namespace rpc
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_RPC_ENCODE_DECODE_LITE_H_
