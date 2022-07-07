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

#include "third_party/sealedcomputing/wasm3/enforcer/fd_socket.h"

#include <endian.h>
#include <errno.h>
#include <unistd.h>

#include <cstdint>
#include <cstring>
#include <string>

#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/logging.h"

namespace sealed {
namespace wasm {

namespace {

Status Read(int fd, uint8_t* buf, size_t size) {
  size_t bytes_read = 0;
  while (bytes_read < size) {
    ssize_t b = read(fd, buf, size - bytes_read);
    if (b < 0) {
      if (errno == EAGAIN || errno == EINTR) {
        continue;
      }
      return Status(kInternal, "error reading fd");
    } else if (b == 0) {
      return Status(kInternal, "reached EOF while reading");
    }
    buf += b;
    bytes_read += b;
  }
  return Status();
}

Status Write(int fd, uint8_t* buf, size_t size) {
  size_t bytes_written = 0;
  while (bytes_written < size) {
    ssize_t b = write(fd, buf, size - bytes_written);
    if (b < 0) {
      if (errno == EAGAIN || errno == EINTR) {
        continue;
      }
      return Status(kInternal, "error writing fd");
    }
    buf += b;
    bytes_written += b;
  }
  return Status();
}

// All serialized envelopes are prefixed with a u32 denoting the length
// (excluding the prefix) of the serialized envelope.
constexpr size_t kEnvelopePrefixLength = sizeof(uint32_t);
constexpr size_t kMaxRpcSize = 1 << 24;

Status DeserializePrefix(uint8_t buf[kEnvelopePrefixLength], uint32_t* length) {
  memcpy(length, buf, kEnvelopePrefixLength);
  SC_CHECK_NOT_NULL(length);
  if (*length > kMaxRpcSize) {
    return Status(kInvalidArgument, "invalid envelope length");
  }
  return Status();
}

Status ReadEnvelope(int in_fd, Envelope* out) {
  uint32_t length = 0;
  {
    ByteString buf(kEnvelopePrefixLength, '\0');
    SC_RETURN_IF_ERROR(Read(in_fd, buf.data(), kEnvelopePrefixLength));
    SC_RETURN_IF_ERROR(DeserializePrefix(buf.data(), &length));
  }
  Envelope incoming_envelope;
  SC_CHECK_NOT_NULL(out);
  {
    ByteString buf(length, '\0');
    SC_RETURN_IF_ERROR(Read(in_fd, buf.data(), length));
    SC_ASSIGN_OR_RETURN(*out, DecodeEnvelope(buf));
  }
  return Status();
}

}  // namespace

FdSocket::FdSocket(const EndpointId& peer, const EndpointId& self,
                   const std::string& socket_id, int in_fd, int out_fd)
    : peer_(peer),
      self_(self),
      socket_id_(socket_id),
      in_fd_(in_fd),
      out_fd_(out_fd) {}

void FdSocket::SendEnvelope(const Envelope& envelope) {
  ByteString encoded_envelope = EncodeEnvelope(envelope);
  uint32_t length = htole32(encoded_envelope.size());
  Write(out_fd_, reinterpret_cast<uint8_t*>(&length), kEnvelopePrefixLength);
  Write(out_fd_, encoded_envelope.data(), encoded_envelope.size());
}

void FdSocket::Send(const ByteString& payload,
                    const SecretByteString& payload_secret) {
  (void)payload_secret;
  Envelope envelope;
  envelope.dst = peer_.string();
  envelope.src = self_.string();
  envelope.socket_id = socket_id_;
  envelope.payload = payload.string();
  SendEnvelope(envelope);
}

Status FdSocket::RecvEnvelope(Envelope* envelope) {
  SC_RETURN_IF_ERROR(ReadEnvelope(in_fd_, envelope));
  return Status();
}

Status FdSocket::Recv(ByteString* payload, SecretByteString* payload_secret) {
  Envelope envelope;
  SC_RETURN_IF_ERROR(RecvEnvelope(&envelope));
  SC_CHECK_NOT_NULL(payload);
  *payload = envelope.payload;
  payload_secret->clear();
  return Status();
}

}  // namespace wasm
}  // namespace sealed
