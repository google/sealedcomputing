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

#include "third_party/sealedcomputing/rpc/rpc.h"

#include <endian.h>
#include <stdlib.h>
#include <string.h>

// ============================================================================
// Encoding
// ============================================================================

#ifdef RPC_NO_MALLOC
// This is the default encoder buffer.  If a larger buffer is needed, or if
// multiple encoders are needed, the RpcSetEncoderBuffer should be called.
static uint8_t global_encoder_buffer[RPC_ENCODE_BUFFER_SIZE];
#endif  // RPC_NO_MALLOC

bool rpcInitEncoderContext(RpcEncoderContext* ctx, bool compress_ints) {
  if (ctx == NULL) {
    return false;
  }
  memset(ctx, 0, sizeof(RpcEncoderContext));
  ctx->compress_ints = compress_ints;
#ifdef RPC_NO_MALLOC
  ctx->buffer = global_encoder_buffer;
  ctx->allocated = sizeof(global_encoder_buffer);
#else
  // Initially allocate a 32 byte size.
  const size_t kInitialBufferLength = 32;
  ctx->buffer = malloc(kInitialBufferLength);
  if (ctx->buffer == NULL) {
    rpcFreeEncoderContext(ctx);
    return false;  // Only possible in OOM conditions.
  }
  ctx->allocated = kInitialBufferLength;
#endif  // RPC_NO_MALLOC
  if (rpcEncodeStartStructure(ctx) != true) {
    rpcFreeEncoderContext(ctx);
    return false;  // Only possible in OOM conditions.
  }
  return true;
}

#ifdef RPC_NO_MALLOC
void rpcEncoderSetBuffer(RpcEncoderContext* ctx, uint8_t* buffer,
                         RpcLengthType buffer_len) {
  ctx->buffer = buffer;
  ctx->allocated = buffer_len;
}
#endif  // RPC_NO_MALLOC

// Zero memory using a volatile pointer so the writes actually happen.
static void zeroMemory(void* buffer, RpcLengthType length) {
  volatile uint8_t* p = buffer;
  while (length-- != 0) {
    *p++ = 0;
  }
}

bool rpcFreeEncoderContext(RpcEncoderContext* ctx) {
  if (ctx == NULL) {
    return false;
  }
  // In case there is secret data in the buffer.
  zeroMemory(ctx->buffer, ctx->length);
#ifndef RPC_NO_MALLOC
  if (ctx->buffer != NULL) {
    free(ctx->buffer);
  }
#endif  // RPC_NO_MALLOC
  ctx->buffer = NULL;
  return true;
}

bool rpcFinishEncoding(RpcEncoderContext* ctx, uint8_t** ret_buffer,
                       RpcLengthType* ret_length) {
  if (ctx == NULL) {
    return false;
  }
  if (!rpcEncodeFinishStructure(ctx)) {
    return false;
  }
  if (ctx->depth != 0) {
    return false;
  }
  if (ret_buffer != NULL) {
    *ret_buffer = ctx->buffer;
  }
  if (ret_length != NULL) {
    *ret_length = ctx->length;
  }
  return true;
}

static bool growEncodeBuffer(RpcEncoderContext* ctx, size_t grow_amount) {
  if (ctx == NULL || grow_amount == 0) {
    return false;  // Should never happen. Untestable.
  }
  size_t new_length = ctx->length + grow_amount;
#ifdef RPC_NO_MALLOC
  if (new_length > ctx->allocated) {
    return false;  // The buffer is full and we can't grow it.
  }
#else
  if (new_length > ctx->allocated) {
    RpcLengthType to_allocate = new_length << 1;
    // Use calloc so we can zero the memory
    void* new_buffer = calloc(to_allocate, sizeof(uint8_t));
    if (!new_buffer) {
      return false;  // Only possible in OOM conditions.
    }
    memcpy(new_buffer, ctx->buffer, ctx->length);
    zeroMemory(ctx->buffer, ctx->length);
    free(ctx->buffer);
    ctx->buffer = new_buffer;
    ctx->allocated = to_allocate;
  }
#endif  // RPC_NO_MALLOC
  ctx->length = new_length;
  return true;
}

// Forward declaration
static bool encodeArrayLength(RpcEncoderContext* ctx, uint32_t value);

// Add a structured element - either a structure or an array.
static bool encodeStartStructuredElement(RpcEncoderContext* ctx,
                                         RpcStructuredType level_type) {
  // Check and increment the depth.
  if (ctx == NULL || ctx->depth == RPC_MAX_LEVELS) {
    return false;
  }
  RpcEncoderLevel* level_ptr = &ctx->levels[ctx->depth];
  level_ptr->level_type = level_type;
  ctx->depth++;
  return true;
}

bool rpcEncodeStartStructure(RpcEncoderContext* ctx) {
  return encodeStartStructuredElement(ctx, kRpcNestedStruct);
}

bool rpcEncodeStartArray(RpcEncoderContext* ctx, RpcLengthType array_count) {
  if (!encodeStartStructuredElement(ctx, kRpcNestedArray)) {
    return false;
  }
  RpcEncoderLevel* level_ptr = &ctx->levels[ctx->depth - 1];
  level_ptr->array_subtype = kRpcUnknownType;  // subtype is not known yet.
  level_ptr->added_count = 0;
  level_ptr->total_count = array_count;
  if (!encodeArrayLength(ctx, array_count)) {
    return false;  // Should only be possible in OOM conditions.
  }
  return true;
}

static bool encodeFinishStructuredElement(RpcEncoderContext* ctx,
                                          RpcStructuredType level_type) {
  if (ctx == NULL || ctx->depth < 1) {
    return false;
  }
  {
    RpcEncoderLevel* level_ptr = &ctx->levels[ctx->depth - 1];
    if (level_type == kRpcNestedArray) {
      if (level_ptr->added_count < level_ptr->total_count) {
        // Some elements are missing.
        return false;
      }
    }
    ctx->depth--;
  }
  if (ctx->depth > 0) {
    RpcEncoderLevel* level_ptr = &ctx->levels[ctx->depth - 1];
    if (level_ptr->level_type == kRpcNestedArray) {
      // This structured element is itself an array element.
      RpcSubType subtype =
          level_type == kRpcNestedArray ? kRpcArrayType : kRpcStructureType;
      if (level_ptr->added_count == 0) {
        // First element, save the type.
        level_ptr->array_subtype = subtype;
      } else {
        // Not the first element, check the type.
        if (level_ptr->array_subtype != subtype) {
          return false;
        }
      }
      level_ptr->added_count++;
    }
  }
  return true;
}

bool rpcEncodeFinishArray(RpcEncoderContext* ctx) {
  return encodeFinishStructuredElement(ctx, kRpcNestedArray);
}

bool rpcEncodeFinishStructure(RpcEncoderContext* ctx) {
  return encodeFinishStructuredElement(ctx, kRpcNestedStruct);
}

static bool encoderUpdateParentArray(RpcEncoderContext* ctx,
                                     RpcSubType type_id) {
  RpcEncoderLevel* level_ptr = &ctx->levels[ctx->depth - 1];
  if (level_ptr->level_type == kRpcNestedArray) {
    // This is an array element.
    if (level_ptr->added_count == 0) {
      // First element, save the type.
      level_ptr->array_subtype = type_id;
    } else {
      // Not the first element, check the type.
      if (level_ptr->array_subtype != type_id) {
        return false;
      }
    }
    level_ptr->added_count++;
  }
  return true;
}

static bool encodeBasicElement(RpcEncoderContext* ctx, RpcSubType type_id,
                               uint8_t value_length, void* value_ptr) {
  if (ctx == NULL || ctx->depth < 1 || value_length == 0 || !value_ptr) {
    return false;
  }
  if (!encoderUpdateParentArray(ctx, type_id)) {
    return false;
  }
  size_t previous_length = ctx->length;
  // Grow buffer first.
  if (!growEncodeBuffer(ctx, value_length)) {
    return false;  // Only possible in OOM conditions.
  }
  // Append copy of value.
  memcpy(ctx->buffer + previous_length, value_ptr, value_length);
  return true;
}

// Return the number of significant bits in a byte, where we define the
// significant bits to be the first bit that is not the same as zeros_or_ones.
// zeros_or_ones should be set to zero unless byte is negative, in which case it
// should be set to 0xFF
static inline uint8_t significantBits(uint8_t byte, uint8_t zeros_or_ones) {
  uint8_t significant_bits = 0;
  byte ^= zeros_or_ones;
  while (byte != 0) {
    significant_bits++;
    byte >>= 1;
  }
  return significant_bits;
}

// Return the number of significant bytes, which remain after we strip off
// leading 0's or 1's.  The zeros_or_ones parameter should be zero unless value
// is negative, in which case it should be set to 0xFF.
static inline uint8_t significantBytes(uint8_t bytes, const uint8_t* value,
                                       uint8_t zeros_or_ones) {
  while (bytes != 0 && value[bytes - 1] == zeros_or_ones) {
    bytes--;
  }
  return bytes;
}

// Compress a little-endian integer bit string. The buffer pointed to by
// ret_value_ptr must hold at least bytes + 1 bytes. The lower bits of the
// first byte return contains the number of following full bytes needed to
// represent the value. The upper bits of the first byte returned contain the
// most significant bits. Signed numbers are presumed to be encoded in 2s
// complement format.
static inline bool compressInt(uint8_t bytes, bool is_signed,
                               const uint8_t* value, uint8_t* ret_value_ptr,
                               uint8_t* ret_length_ptr) {
  if (bytes < 2 || value == NULL || ret_value_ptr == NULL ||
      ret_length_ptr == NULL) {
    return false;
  }
  uint8_t zeros_or_ones = 0;
  if (is_signed && (value[bytes - 1] & 0x80) != 0) {
    zeros_or_ones = 0xff;
  }
  uint8_t full_bytes = significantBytes(bytes, value, zeros_or_ones);
  uint8_t msB = zeros_or_ones;
  uint8_t byte_count_bits = significantBits(bytes, 0);
  if (full_bytes != 0) {
    uint8_t high_full_byte = value[full_bytes - 1];
    uint8_t msB_bits = significantBits(high_full_byte, zeros_or_ones);
    if (byte_count_bits + msB_bits + is_signed <= 8) {
      // We can fit the most significant bits in the first byte.
      full_bytes -= 1;
      msB = high_full_byte;
    }
  }
  // Store the count of full following bytes in first byte prefix.
  ret_value_ptr[0] = full_bytes;
  // First, copy all full bytes.
  memcpy(&ret_value_ptr[1], value, full_bytes);
  // Then, copy overflow bits.
  ret_value_ptr[0] |= msB << byte_count_bits;
  *ret_length_ptr = full_bytes + 1;
  return true;
}

bool rpcTestCompressInt(uint8_t bytes, bool is_signed, const uint8_t* value,
                        uint8_t* ret_value_ptr, uint8_t* ret_length_ptr) {
  return compressInt(bytes, is_signed, value, ret_value_ptr, ret_length_ptr);
}

// Uncompress integer.
static inline bool uncompressInt(uint8_t bytes, bool is_signed,
                                 const uint8_t* compressed_value_ptr,
                                 uint8_t compressed_buffer_length,
                                 uint8_t* ret_value_ptr,
                                 uint8_t* ret_compressed_length) {
  if (bytes < 2 || compressed_value_ptr == NULL ||
      compressed_buffer_length == 0 || ret_value_ptr == NULL ||
      ret_compressed_length == NULL) {
    return false;
  }
  uint8_t byte_count_bits = significantBits(bytes, 0);
  uint8_t prefix_byte = compressed_value_ptr[0];
  uint8_t full_bytes = prefix_byte & ((1 << byte_count_bits) - 1);
  bool is_negative = is_signed && (prefix_byte & 0x80);
  uint8_t actual_length = full_bytes + 1;
  if (actual_length > compressed_buffer_length || full_bytes > bytes) {
    // We are missing part of the data, or there are too many bytes.
    return false;
  }
  *ret_compressed_length = actual_length;
  // First, copy all full bytes.
  memcpy(ret_value_ptr, &compressed_value_ptr[1], full_bytes);
  uint8_t msB;
  uint8_t zeros_or_ones = 0;
  if (is_negative) {
    msB = (int8_t)prefix_byte >> byte_count_bits;
    zeros_or_ones = 0xFF;
  } else {
    msB = prefix_byte >> byte_count_bits;
  }
  uint8_t copied_bytes = full_bytes;
  if (msB != zeros_or_ones) {
    // Extract most significant bits from prefix byte.
    if (copied_bytes == bytes) {
      return false;  // Too many bytes.
    }
    ret_value_ptr[copied_bytes++] = msB;
  } else if (full_bytes != 0) {
    uint8_t high_full_byte = compressed_value_ptr[full_bytes];
    uint8_t high_full_byte_bits =
        significantBits(high_full_byte, zeros_or_ones);
    if (high_full_byte_bits + byte_count_bits + is_signed <= 8) {
      return false;  // Should have encoded in fewer bytes.
    }
    if (is_signed && full_bytes == bytes && ((msB ^ high_full_byte) & 0x80)) {
      return false;  // Mismatched sign of value vs prefix byte.
    }
  }
  uint8_t remaining_bytes = bytes - copied_bytes;
  memset(&ret_value_ptr[bytes - remaining_bytes], zeros_or_ones,
         remaining_bytes);
  return true;
}

bool rpcTestUncompressInt(uint8_t bytes, bool is_signed,
                          const uint8_t* compressed_value_ptr,
                          uint8_t compressed_buffer_length,
                          uint8_t* ret_value_ptr,
                          uint8_t* ret_compressed_length) {
  return uncompressInt(bytes, is_signed, compressed_value_ptr,
                       compressed_buffer_length, ret_value_ptr,
                       ret_compressed_length);
}

static bool encodeInteger(RpcEncoderContext* ctx, RpcSubType type_id,
                          uint8_t value_length, bool is_signed, void* value_ptr,
                          bool is_array_length) {
  if (ctx == NULL || ctx->depth < 1 || value_length == 0 || !value_ptr) {
    return false;
  }
  if (!is_array_length) {
    if (!encoderUpdateParentArray(ctx, type_id)) {
      return false;
    }
  }
  size_t previous_length = ctx->length;
  // Grow buffer first. Allocate one extra byte for prefix.
  size_t grow_amount = value_length + 1;
  if (!growEncodeBuffer(ctx, grow_amount)) {
    return false;  // Only possible in OOM conditions.
  }
  if (ctx->compress_ints || is_array_length) {
    uint8_t compressed_length = 0;
    if (!compressInt(value_length, is_signed, (uint8_t*)value_ptr,
                     ctx->buffer + previous_length, &compressed_length)) {
      return false;  // Should never happen. Untestable.
    }
    // Reset buffer length based on integer's compressed length.
    ctx->length = previous_length + compressed_length;
  } else {
    memcpy(ctx->buffer + previous_length, value_ptr, value_length);
    ctx->length = previous_length + value_length;
  }
  return true;
}

bool rpcEncodeU8(RpcEncoderContext* ctx, uint8_t value) {
  return encodeBasicElement(ctx, kRpcU8Type, sizeof(value), &value);
}

bool rpcEncodeS8(RpcEncoderContext* ctx, int8_t value) {
  return encodeBasicElement(ctx, kRpcS8Type, sizeof(value), &value);
}

bool rpcEncodeU16(RpcEncoderContext* ctx, uint16_t value) {
  value = htole16(value);
  return encodeInteger(ctx, kRpcU16Type, sizeof(value), false, &value, false);
}

bool rpcEncodeS16(RpcEncoderContext* ctx, int16_t value) {
  value = htole16(value);
  return encodeInteger(ctx, kRpcS16Type, sizeof(value), true, &value, false);
}

// Encode array length. Length is a u32.
static bool encodeArrayLength(RpcEncoderContext* ctx, uint32_t value) {
  value = htole32(value);
  return encodeInteger(ctx, kRpcU32Type, sizeof(value), false, &value, true);
}

bool rpcEncodeU32(RpcEncoderContext* ctx, uint32_t value) {
  value = htole32(value);
  return encodeInteger(ctx, kRpcU32Type, sizeof(value), false, &value, false);
}

bool rpcEncodeS32(RpcEncoderContext* ctx, int32_t value) {
  value = htole32(value);
  return encodeInteger(ctx, kRpcS32Type, sizeof(value), true, &value, false);
}

bool rpcEncodeU64(RpcEncoderContext* ctx, uint64_t value) {
  value = htole64(value);
  return encodeInteger(ctx, kRpcU64Type, sizeof(value), false, &value, false);
}

bool rpcEncodeS64(RpcEncoderContext* ctx, int64_t value) {
  value = htole64(value);
  return encodeInteger(ctx, kRpcS64Type, sizeof(value), true, &value, false);
}

bool rpcEncodeF32(RpcEncoderContext* ctx, float value) {
  uint32_t int_val = *(uint32_t*)&value;
  int_val = htole32(int_val);
  return encodeBasicElement(ctx, kRpcF32Type, sizeof(int_val), &int_val);
}

bool rpcEncodeF64(RpcEncoderContext* ctx, double value) {
  uint64_t int_val = *(uint64_t*)&value;
  int_val = htole64(int_val);
  return encodeBasicElement(ctx, kRpcF64Type, sizeof(int_val), &int_val);
}

// ============================================================================
// Decoding
// ============================================================================

bool rpcInitDecoderContext(RpcDecoderContext* ctx, bool compress_ints,
                           const void* data, size_t length) {
  if (ctx == NULL) {
    return false;
  }
  memset(ctx, 0, sizeof(RpcDecoderContext));
  ctx->compress_ints = compress_ints;
  ctx->buffer = data;
  ctx->length = length;
  if (!rpcDecodeStartStructure(ctx)) {
    // Should never happen. Untestable.
    rpcFreeDecoderContext(ctx);
    return false;
  }
  return true;
}

bool rpcFreeDecoderContext(RpcDecoderContext* ctx) { return ctx != NULL; }

bool rpcFinishDecoding(RpcDecoderContext* ctx) {
  if (ctx == NULL) {
    return false;
  }
  if (!rpcDecodeFinishStructure(ctx)) {
    return false;
  }
  if (ctx->depth != 0) {
    // We still have an array or structure that's not been fully decoded.
    return false;
  }
  if (ctx->current_offset != ctx->length) {
    // We haven't decoded everything.
    return false;
  }
  return true;
}

static bool decoderUpdateParentArray(RpcDecoderContext* ctx,
                                     RpcSubType type_id) {
  RpcDecoderLevel* level_ptr = &ctx->levels[ctx->depth - 1];
  if (level_ptr->level_type == kRpcNestedArray) {
    // This is an array element.
    RpcLengthType remaining =
        level_ptr->total_count - level_ptr->retrieved_count;
    if (remaining == 0) {
      return false;  // All elements have been read.
    }
    if (level_ptr->retrieved_count == 0) {
      // First element, retrieve the type.
      level_ptr->array_subtype = type_id;
    } else {
      // Not the first element, check the type.
      if (level_ptr->array_subtype != type_id) {
        return false;
      }
    }
    level_ptr->retrieved_count++;
  }
  return true;
}

// Read an element of length value_length.
static bool decodeBasicElement(RpcDecoderContext* ctx, RpcSubType type_id,
                               uint8_t value_length, void* ret_value_ptr) {
  if (ctx == NULL || !value_length || ctx->depth < 1) {
    return false;
  }
  if (!decoderUpdateParentArray(ctx, type_id)) {
    return false;
  }
  // Retrieve value.
  if (value_length > (ctx->length - ctx->current_offset)) {
    return false;
  }
  memcpy(ret_value_ptr, ctx->buffer + ctx->current_offset, value_length);

  ctx->current_offset += value_length;
  return true;
}

static bool decodeInteger(RpcDecoderContext* ctx, RpcSubType type_id,
                          uint8_t value_length, bool is_signed,
                          void* ret_value_ptr, bool is_array_length) {
  if (ctx == NULL || !value_length || ctx->depth < 1 || !ret_value_ptr) {
    return false;
  }
  if (!is_array_length) {
    if (!decoderUpdateParentArray(ctx, type_id)) {
      return false;
    }
  }
  // Compressed element. It may be up to one byte larger than value_length.
  const uint8_t max_read_length = value_length + 1;
  size_t remaining = ctx->length - ctx->current_offset;
  if (!remaining) {
    return false;
  }
  uint8_t to_process =
      remaining > max_read_length ? max_read_length : remaining;
  const uint8_t* compressed_value = ctx->buffer + ctx->current_offset;
  uint8_t actual_length = 0;
  if (ctx->compress_ints || is_array_length) {
    if (!uncompressInt(value_length, is_signed, compressed_value, to_process,
                       (uint8_t*)ret_value_ptr, &actual_length)) {
      return false;
    }
    ctx->current_offset += actual_length;
  } else {
    if (remaining < value_length) {
      return false;
    }
    memcpy(ret_value_ptr, compressed_value, value_length);
    ctx->current_offset += value_length;
  }
  return true;
}

bool rpcDecodeU8(RpcDecoderContext* ctx, uint8_t* ret_value_ptr) {
  return decodeBasicElement(ctx, kRpcU8Type, sizeof(*ret_value_ptr),
                            ret_value_ptr);
}

bool rpcDecodeS8(RpcDecoderContext* ctx, int8_t* ret_value_ptr) {
  return decodeBasicElement(ctx, kRpcS8Type, sizeof(*ret_value_ptr),
                            ret_value_ptr);
}

bool rpcDecodeU16(RpcDecoderContext* ctx, uint16_t* ret_value_ptr) {
  if (!decodeInteger(ctx, kRpcU16Type, sizeof(*ret_value_ptr), false,
                     ret_value_ptr, false)) {
    return false;
  }
  *ret_value_ptr = le16toh(*ret_value_ptr);
  return true;
}

bool rpcDecodeS16(RpcDecoderContext* ctx, int16_t* ret_value_ptr) {
  if (!decodeInteger(ctx, kRpcS16Type, sizeof(*ret_value_ptr), true,
                     ret_value_ptr, false)) {
    return false;
  }
  *ret_value_ptr = le16toh(*ret_value_ptr);
  return true;
}

// Decode array length. Length is a u32.
static bool decodeArrayLength(RpcDecoderContext* ctx, uint32_t* ret_value_ptr) {
  if (!decodeInteger(ctx, kRpcU32Type, sizeof(*ret_value_ptr), false,
                     ret_value_ptr, true)) {
    return false;
  }
  *ret_value_ptr = le32toh(*ret_value_ptr);
  return true;
}

bool rpcDecodeU32(RpcDecoderContext* ctx, uint32_t* ret_value_ptr) {
  if (!decodeInteger(ctx, kRpcU32Type, sizeof(*ret_value_ptr), false,
                     ret_value_ptr, false)) {
    return false;
  }
  *ret_value_ptr = le32toh(*ret_value_ptr);
  return true;
}

bool rpcDecodeS32(RpcDecoderContext* ctx, int32_t* ret_value_ptr) {
  if (!decodeInteger(ctx, kRpcS32Type, sizeof(*ret_value_ptr), true,
                     ret_value_ptr, false)) {
    return false;
  }
  *ret_value_ptr = le32toh(*ret_value_ptr);
  return true;
}

bool rpcDecodeU64(RpcDecoderContext* ctx, uint64_t* ret_value_ptr) {
  if (!decodeInteger(ctx, kRpcU64Type, sizeof(*ret_value_ptr), false,
                     ret_value_ptr, false)) {
    return false;
  }
  *ret_value_ptr = le64toh(*ret_value_ptr);
  return true;
}

bool rpcDecodeS64(RpcDecoderContext* ctx, int64_t* ret_value_ptr) {
  if (!decodeInteger(ctx, kRpcS64Type, sizeof(*ret_value_ptr), true,
                     ret_value_ptr, false)) {
    return false;
  }
  *ret_value_ptr = le64toh(*ret_value_ptr);
  return true;
}

bool rpcDecodeF32(RpcDecoderContext* ctx, float* ret_value_ptr) {
  bool status = decodeBasicElement(ctx, kRpcF32Type, sizeof(*ret_value_ptr),
                                   ret_value_ptr);
  if (status && ret_value_ptr) {
    *(uint32_t*)ret_value_ptr = le32toh(*(uint32_t*)ret_value_ptr);
  }
  return status;
}

bool rpcDecodeF64(RpcDecoderContext* ctx, double* ret_value_ptr) {
  bool status = decodeBasicElement(ctx, kRpcF64Type, sizeof(*ret_value_ptr),
                                   ret_value_ptr);
  if (status && ret_value_ptr) {
    *(uint64_t*)ret_value_ptr = le64toh(*(uint64_t*)ret_value_ptr);
  }
  return status;
}

// Retrieve a structured element - either a structure or an array.
static bool decodeStartStructuredElement(RpcDecoderContext* ctx,
                                         RpcStructuredType level_type) {
  if (ctx == NULL || ctx->depth == RPC_MAX_LEVELS) {
    return false;
  }
  RpcDecoderLevel* level_ptr = &ctx->levels[ctx->depth];
  level_ptr->level_type = level_type;
  ctx->depth += 1;
  return true;
}

bool rpcDecodeStartArray(RpcDecoderContext* ctx,
                         RpcLengthType* ret_array_count_ptr) {
  if (!decodeStartStructuredElement(ctx, kRpcNestedArray)) {
    return false;
  }
  RpcDecoderLevel* level_ptr = &ctx->levels[ctx->depth] - 1;
  // Retrieve array element count.
  if (!decodeArrayLength(ctx, &level_ptr->total_count)) {
    return false;
  }
  if (ret_array_count_ptr) {
    *ret_array_count_ptr = level_ptr->total_count;
  }
  level_ptr->retrieved_count = 0;
  level_ptr->array_subtype = kRpcUnknownType;  // subtype is not known yet
  return true;
}

bool rpcDecodeStartStructure(RpcDecoderContext* ctx) {
  return decodeStartStructuredElement(ctx, kRpcNestedStruct);
}

static bool decodeFinishComplexElement(RpcDecoderContext* ctx,
                                       RpcStructuredType level_type) {
  if (ctx == NULL || ctx->depth < 1) {
    return false;
  }
  if (level_type == kRpcNestedArray) {
    // This is an array. Make sure we have read every element.
    RpcDecoderLevel* level_ptr = &ctx->levels[ctx->depth - 1];
    if (level_ptr->retrieved_count != level_ptr->total_count) {
      return false;
    }
  }
  ctx->depth -= 1;
  if (ctx->depth > 0) {
    RpcDecoderLevel* parent_level_ptr = &ctx->levels[ctx->depth - 1];
    if (parent_level_ptr->level_type == kRpcNestedArray) {
      // This structured structure is itself an array element.
      RpcSubType subtype =
          level_type == kRpcNestedArray ? kRpcArrayType : kRpcStructureType;
      if (parent_level_ptr->retrieved_count == 0) {
        // First element, save the type.
        parent_level_ptr->array_subtype = subtype;
      } else {
        // Not the first element, check the type.
        if (parent_level_ptr->array_subtype != subtype) {
          return false;
        }
      }
      parent_level_ptr->retrieved_count++;
    }
  }
  return true;
}

bool rpcDecodeFinishArray(RpcDecoderContext* ctx) {
  return decodeFinishComplexElement(ctx, kRpcNestedArray);
}

bool rpcDecodeFinishStructure(RpcDecoderContext* ctx) {
  return decodeFinishComplexElement(ctx, kRpcNestedStruct);
}
