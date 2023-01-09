//  Copyright 2021 Google LLC.
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

// This is a nanolibc UEFI application that simply reads in a Sealed RPC request
// from the SimpleSevIo device and sends back a Sealed RPC response on the same
// device.

#include <assert.h>
#include <endian.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <cstdint>

#include "cloud/vmm/subsystems/simple_sev_io/consts.h"
#include "cloud/vmm/subsystems/simple_sev_io/simple_sev_io_guest.h"
#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/enforcer/envelope.common.h"
#include "third_party/sealedcomputing/wasm3/enforcer/rpc.common.h"
#include "third_party/sealedcomputing/wasm3/enforcer/status_encode_decode.h"
#include "third_party/sealedcomputing/wasm3/status.h"

// Use the same input and output lengths because we're an echo app.
constexpr uint32_t kOutLen = kSimpleSevIoInputBufferLength;

using ::sealed::wasm::ByteString;
using ::sealed::wasm::Envelope;
using ::sealed::wasm::kInternal;
using ::sealed::wasm::kInvalidArgument;
using ::sealed::wasm::RpcMessage;
using ::sealed::wasm::Status;
using ::sealed::wasm::StatusOr;

StatusOr<Envelope> ReadEnvelope() {
  int32_t read_len = 0;
  const void* read_buf;
  while (read_len == 0) {
    read_buf = simple_sev_io::SevIoRead(&read_len);
  }
  if (read_len < 0) {
    return Status(kInternal, "error reading from SevIoDevice");
  }
  if (static_cast<size_t>(read_len) < sizeof(uint32_t)) {
    printf("echo_envelope: read %d bytes\n", read_len);
    return Status(kInvalidArgument, "less than 4 bytes read");
  }

  uint32_t encoded_envelope_length;
  memcpy(&encoded_envelope_length, read_buf, sizeof(uint32_t));
  if (read_len - sizeof(uint32_t) != encoded_envelope_length) {
    return Status(kInvalidArgument, "lengths do not match");
  }
  printf("echo_envelope: length checks out\n");

  ByteString encoded_request_envelope(encoded_envelope_length);
  const uint8_t* data =
      reinterpret_cast<const uint8_t*>(read_buf) + sizeof(uint32_t);
  auto envelope =
      sealed::wasm::DecodeEnvelope(ByteString(data, encoded_envelope_length));
  if (!envelope) {
    return Status(kInvalidArgument,
                  "error decoding envelope read from SevIoDevice");
  }
  return *envelope;
}

void WriteRpcMessage(const RpcMessage& rpc_message, const ByteString& socket_id,
                     uint8_t* out) {
  Envelope envelope;
  envelope.socket_id = socket_id;
  envelope.payload = sealed::wasm::EncodeRpcMessage(rpc_message).public_data;
  ByteString encoded_envelope = sealed::wasm::EncodeEnvelope(envelope);
  uint32_t envelope_length = htole32(encoded_envelope.size());

  memcpy(out, &envelope_length, sizeof(uint32_t));
  memcpy(out + sizeof(uint32_t), encoded_envelope.data(),
         encoded_envelope.size());
  size_t output_length = sizeof(uint32_t) + envelope_length;
  printf("echo_envelope: wrote %zu bytes output", output_length);
  simple_sev_io::SevIoFlushOutputBuffer(output_length);
}

void WriteStatus(const Status& status, const ByteString& socket_id,
                 uint8_t* out) {
  RpcMessage message;
  message.type = sealed::wasm::RpcType::RPC_TYPE_RESPONSE;
  message.encoded_status = sealed::wasm::EncodeStatus(status);
  WriteRpcMessage(message, socket_id, out);
}

int main() {
  simple_sev_io::SevIoInit(kOutLen);
  uint8_t* out =
      reinterpret_cast<uint8_t*>(simple_sev_io::SevIoOutputGetBuffer());

  printf("testapp ready\n");

  while (true) {
    auto envelope = ReadEnvelope();
    if (!envelope) {
      // No socket_id in request to route the response to.
      WriteStatus(envelope.status(), "", out);
      continue;
    }

    auto rpc_message =
        sealed::wasm::DecodeRpcMessage(ByteString(envelope->payload));
    if (!rpc_message) {
      WriteStatus(rpc_message.status(), envelope->socket_id, out);
      continue;
    }
    printf("echo_envelope: successfully decoded RpcMessage");

    RpcMessage response_message;
    response_message.type = sealed::wasm::RpcType::RPC_TYPE_RESPONSE;
    response_message.payload = rpc_message->payload;
    WriteRpcMessage(response_message, envelope->socket_id, out);
  }
}
