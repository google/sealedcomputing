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

#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "third_party/sealedcomputing/wasm3/enforcer/fd_socket.h"
#include "third_party/sealedcomputing/wasm3/enforcer/wasm.h"
#include "third_party/sealedcomputing/wasm3/status.h"

// Instead of reading the bytecode from a file, read it from stdin.  The first
// message sent from the Sealet to the Enforcer must be the bytecode, as an
// encoded string.
int main() {
  sealed::wasm::FdSocket socket(/*peer=*/"", /*self=*/"", /*socket_id=*/"",
                                STDIN_FILENO,
                                /*out_fd=*/-1);
  sealed::wasm::Envelope envelope;
  sealed::wasm::Status status = socket.RecvEnvelope(&envelope);
  if (!status.ok()) {
    fprintf(stderr, "Unable to read wasm bytecode from stdin: %s\n",
            status.message().c_str());
    return 1;
  }
  status = sealed::wasm::InitWasm(envelope.payload);
  if (!status) {
    fprintf(stderr, "Unable start bytecode interpreter: %s\n",
            status.message().c_str());
    return 1;
  }
  status = sealed::wasm::RunWasmMain();
  return !status;
}
