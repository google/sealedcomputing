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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_TEST_FD_SOCKET_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_TEST_FD_SOCKET_H_

#include "third_party/sealedcomputing/wasm3/enforcer/envelope.common.h"
#include "third_party/sealedcomputing/wasm3/enforcer/fd_socket.h"

namespace sealed::wasm {

// Functionally identical to `FdSocket` except
// - logs all envelopes sent and received,
// - when blocking on `Recv` and `RecvEnvelope`, yields the current
//   `thread::Fiber` too. This allows us to use google3-specific `thread::Fiber`
//   libraries in tests.
class TestFdSocket : public FdSocket {
 public:
  TestFdSocket(const EndpointId& peer, const EndpointId& self,
               const std::string& socket_id, int in_fd, int out_fd)
      : FdSocket(peer, self, socket_id, in_fd, out_fd) {}

  Status RecvEnvelope(Envelope* envelope) override;

  void SendEnvelope(const Envelope& envelope) override;
};

// Returns a unidirectional, read-only `TestFdSocket` from a given file
// descriptor `in_fd`. Does not take ownership of `in_fd`.
inline std::unique_ptr<SocketInternal> MakeReadOnlyFdSocket(int in_fd) {
  return std::make_unique<TestFdSocket>(/*peer=*/"", /*self=*/"",
                                        /*socket_id=*/"", in_fd, /*out_fd=*/-1);
}

// Returns a unidirectional, write-only `TestFdSocket` from a given file
// descriptor `out_fd`. Does not take ownership of `out_fd`.
inline std::unique_ptr<SocketInternal> MakeWriteOnlyFdSocket(int out_fd) {
  return std::make_unique<TestFdSocket>(/*peer=*/"", /*self=*/"",
                                        /*socket_id=*/"", /*in_fd=*/-1, out_fd);
}

}  // namespace sealed::wasm

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_TEST_FD_SOCKET_H_
