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

#include "third_party/sealedcomputing/wasm3/enforcer/test_fd_socket.h"

#include <sstream>

#include "base/logging.h"
#include "base/scheduling/domain.h"

namespace sealed::wasm {
namespace {

std::string DumpEnvelope(const Envelope& envelope) {
  std::ostringstream output;
  output << "Dumping envelope: "
         << "\n  dst: " << ByteString(envelope.dst).hex()
         << "\n  src: " << ByteString(envelope.src).hex()
         << "\n  socket_id: " << ByteString(envelope.socket_id).hex()
         << "\n  payload_type: "
         << ByteString(static_cast<size_t>(envelope.payload_type)).hex()
         << "\n  payload: " << ByteString(envelope.payload).hex()
         << "\n  encrypted_payload: "
         << ByteString(envelope.encrypted_payload).hex()
         << "\n  session_envelope_num: " << envelope.session_envelope_num
         << "\n  mac: " << ByteString(envelope.mac).hex() << std::endl;
  return output.str();
}

}  // namespace

Status TestFdSocket::RecvEnvelope(Envelope* envelope) {
  // This ensures that the `RecvEnvelope` call also yields the `thread::Fiber`
  // allowing us to use `thread::Fiber` in tests to emulate multiple SC
  // endpoints.
  base::scheduling::PotentiallyBlockingRegion region;
  SC_RETURN_IF_ERROR(FdSocket::RecvEnvelope(envelope));
  LOG(INFO) << "Receiving envelope: " << DumpEnvelope(*envelope);
  return Status();
}

void TestFdSocket::SendEnvelope(const Envelope& envelope) {
  LOG(INFO) << "Sending envelope: " << DumpEnvelope(envelope);
  FdSocket::SendEnvelope(envelope);
}

}  // namespace sealed::wasm
