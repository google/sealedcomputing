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
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "third_party/sealedcomputing/wasm3/enforcer/fd_socket.h"
#include "third_party/sealedcomputing/wasm3/enforcer/wasm.h"
#include "third_party/sealedcomputing/wasm3/status.h"

int main(int argc, const char** argv) {
  sealed::wasm::Status status;
  std::string in_bytes;
  if (argc == 2) {
    // bytecode file specified on command line.
    fprintf(stderr, "Running enforcer with wasm binary %s\n", argv[1]);
    std::ifstream in_wasm(argv[1]);
    std::stringstream buffer;
    buffer << in_wasm.rdbuf();
    in_bytes = buffer.str();
  } else if (argc == 1) {
    // No bytecode specified.  Read it in the first envelope;
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
    in_bytes = envelope.payload;
  } else {
    fprintf(stderr, "Usage: %s wasm_bytecode_file\n", argv[0]);
    return 1;
  }
  status = sealed::wasm::InitWasm(in_bytes);
  if (!status) {
    return 1;
  }
  status = sealed::wasm::RunWasmMain();
  return !status;
}
