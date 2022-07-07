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

#ifndef THIRD_PARTY_SEALED_COMPUTING_RPC_H
#define THIRD_PARTY_SEALED_COMPUTING_RPC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

// Used for structure length and array element count.
typedef uint32_t RpcLengthType;

#define RPC_MAX_LEVELS 10  // max levels of nesting for structures and array

// If RPC_NO_MALLOC is defined, a static buffer of size RPC_ENCODE_BUFFER_SIZE
// is added to the context itself.
#if defined(RPC_NO_MALLOC) && !defined(RPC_ENCODE_BUFFER_SIZE)
#define RPC_ENCODE_BUFFER_SIZE 256
#endif

typedef enum { kRpcNestedStruct, kRpcNestedArray } RpcStructuredType;

typedef enum {
  kRpcUnknownType,
  kRpcU8Type,
  kRpcS8Type,
  kRpcU16Type,
  kRpcS16Type,
  kRpcU32Type,
  kRpcS32Type,
  kRpcU64Type,
  kRpcS64Type,
  kRpcF32Type,
  kRpcF64Type,
  kRpcStructureType,
  kRpcArrayType,
} RpcSubType;

// Both encode and decode have a fixed-sized stack of "levels" that hold data
// used during encoding/decoding.  For example, arrays have a "count" used to
// keep track of the number of elements encoded.
typedef struct {
  RpcStructuredType level_type;  // struct or array
  // For arrays only. Number of elements. Encoded in RPC buffer. Type checking
  // happens on element 2+
  RpcLengthType total_count;
  // For arrays only. Count of elements actually encoded.
  RpcLengthType added_count;
  RpcSubType array_subtype;
} RpcEncoderLevel;

typedef struct {
  uint8_t* buffer;
  // Represents the amount of the buffer used so far.
  RpcLengthType length;
  // Represents the total available space in the buffer.
  RpcLengthType allocated;
  uint16_t depth;  // Current stack depth.
  RpcEncoderLevel levels[RPC_MAX_LEVELS];
  bool compress_ints;
} RpcEncoderContext;

// Both encode and decode have a fixed-sized stack of "levels" that hold data
// used during encoding/decoding.  For example, arrays have a "count" used to
// keep track of the number of elements encoded.
typedef struct {
  RpcStructuredType level_type;  // struct or array
  // For arrays only. Number of elements. Encoded in RPC buffer Type checking
  // happens on element 2+.
  RpcLengthType total_count;
  // For arrays only. Number of elements already.
  RpcLengthType retrieved_count;
  // Read from array.
  RpcSubType array_subtype;
} RpcDecoderLevel;

typedef struct {
  // Represents the length of the input buffer.
  size_t length;
  const uint8_t* buffer;
  uint16_t depth;  // Current stack depth.
  RpcLengthType current_offset;
  RpcDecoderLevel levels[RPC_MAX_LEVELS];
  bool compress_ints;
} RpcDecoderContext;

// Initialize the context pointed to by `ctx`.  It normally is a local variable
// in the caller.  If compress_ints is false, don't compress integers which are
// potentially secret.  Compression leaks information about the values.
bool rpcInitEncoderContext(RpcEncoderContext* ctx, bool compress_ints);
#ifdef RPC_NO_MALLOC
// On systems with no malloc, this function can be used to set the buffer to
// something other than the default static buffer.  It MUST be called after the
// context is initialized with rpcInitEncoderContext.
void rpcEncoderSetBuffer(RpcEncoderContext* ctx, uint8_t* buffer,
                         RpcLengthType buffer_len);
#endif
// Call after last element has been encoded.
bool rpcFinishEncoding(RpcEncoderContext* ctx, uint8_t** ret_buffer,
                       RpcLengthType* ret_length);
bool rpcFreeEncoderContext(RpcEncoderContext* ctx);

inline RpcLengthType rpcEncoderGetAllocated(RpcEncoderContext* ctx) {
  return ctx->allocated;
}
bool rpcEncodeU8(RpcEncoderContext* ctx, uint8_t value);
bool rpcEncodeS8(RpcEncoderContext* ctx, int8_t value);
bool rpcEncodeU16(RpcEncoderContext* ctx, uint16_t value);
bool rpcEncodeS16(RpcEncoderContext* ctx, int16_t value);
bool rpcEncodeU32(RpcEncoderContext* ctx, uint32_t value);
bool rpcEncodeS32(RpcEncoderContext* ctx, int32_t value);
bool rpcEncodeU64(RpcEncoderContext* ctx, uint64_t value);
bool rpcEncodeS64(RpcEncoderContext* ctx, int64_t value);
bool rpcEncodeF32(RpcEncoderContext* ctx, float value);
bool rpcEncodeF64(RpcEncoderContext* ctx, double value);
bool rpcEncodeStartArray(RpcEncoderContext* ctx, RpcLengthType array_count);
bool rpcEncodeFinishArray(RpcEncoderContext* ctx);
bool rpcEncodeStartStructure(RpcEncoderContext* ctx);
bool rpcEncodeFinishStructure(RpcEncoderContext* ctx);

// Pass in buffer when creating a decoder context.  The lifetime of the buffer
// must last as long as the decoder is in use.  `ctx` is usually a local on
// the stack of the caller.  If `decompress_ints` is false, don't decompress
// integers other than lengths.  This is needed when decoding secret data.
bool rpcInitDecoderContext(RpcDecoderContext* ctx, bool decompress_ints,
                           const void* data, size_t length);
bool rpcFinishDecoding(RpcDecoderContext* ctx);
bool rpcFreeDecoderContext(RpcDecoderContext* ctx);

bool rpcDecodeU8(RpcDecoderContext* ctx, uint8_t* ret_value_ptr);
bool rpcDecodeS8(RpcDecoderContext* ctx, int8_t* ret_value_ptr);
bool rpcDecodeU16(RpcDecoderContext* ctx, uint16_t* ret_value_ptr);
bool rpcDecodeS16(RpcDecoderContext* ctx, int16_t* ret_value_ptr);
bool rpcDecodeU32(RpcDecoderContext* ctx, uint32_t* ret_value_ptr);
bool rpcDecodeS32(RpcDecoderContext* ctx, int32_t* ret_value_ptr);
bool rpcDecodeU64(RpcDecoderContext* ctx, uint64_t* ret_value_ptr);
bool rpcDecodeS64(RpcDecoderContext* ctx, int64_t* ret_value_ptr);
bool rpcDecodeF32(RpcDecoderContext* ctx, float* ret_value_ptr);
bool rpcDecodeF64(RpcDecoderContext* ctx, double* ret_value_ptr);
bool rpcDecodeStartArray(RpcDecoderContext* ctx,
                         RpcLengthType* ret_array_count_ptr);
bool rpcDecodeFinishArray(RpcDecoderContext* ctx);
bool rpcDecodeStartStructure(RpcDecoderContext* ctx);
bool rpcDecodeFinishStructure(RpcDecoderContext* ctx);

// The following functions are just for tests and not part of the public API.
bool rpcTestCompressInt(uint8_t bytes, bool is_signed, const uint8_t* value,
                        uint8_t* ret_value_ptr, uint8_t* ret_length_ptr);

bool rpcTestUncompressInt(uint8_t bytes, bool is_signed,
                          const uint8_t* compressed_value_ptr,
                          uint8_t compressed_buffer_length,
                          uint8_t* ret_value_ptr,
                          uint8_t* ret_compressed_length);

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // THIRD_PARTY_SEALED_COMPUTING_RPC_H
