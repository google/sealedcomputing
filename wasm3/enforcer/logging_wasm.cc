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

#include <cstdint>

#include "third_party/sealedcomputing/wasm3/enforcer/builtin_impl.h"
#include "third_party/sealedcomputing/wasm3/enforcer/server.h"
#include "third_party/sealedcomputing/wasm3/enforcer/wasm.h"
#include "third_party/sealedcomputing/wasm3/logging.h"

namespace {

const char* kLevelNames[] = {"INFO", "WARNING", "ERROR", "FATAL", "DEBUG"};

}  // namespace

m3ApiRawFunction(biPanic_wrapper) {
  m3ApiGetArgMem(const void*, filename);
  m3ApiGetArg(int32_t, line);
  m3ApiGetArgMem(const void*, text);
  if (!sealed::wasm::MemCheckCstr(filename)) {
    filename = "Bad file_name pointer passed to biPanic";
  }
  if (!sealed::wasm::MemCheckCstr(text)) {
    text = "Bad text pointer passed to biPanic";
  }
  biPanic(filename, line, text);
  // We don't get here.
  m3ApiTrap(m3Err_trapAbort);
}

void biPanic(const void* filename, int32_t line, const void* text) {
  biSendLogRpc(FATAL, filename, line, text);
}

m3ApiRawFunction(biSendLogRpc_wrapper) {
  m3ApiGetArg(int32_t, level);
  m3ApiGetArgMem(const void*, filename);
  m3ApiGetArg(int32_t, line);
  m3ApiGetArgMem(const void*, text);
  if (!sealed::wasm::MemCheckCstr(filename)) {
    filename = "Bad file_name pointer passed to biPanic";
    level = FATAL;
  }
  if (!sealed::wasm::MemCheckCstr(text)) {
    text = "Bad text pointer passed to biSendLogRpc";
    level = FATAL;
  }
  biSendLogRpc(level, filename, line, text);
  m3ApiSuccess();
}

void biSendLogRpc(int32_t level, const void* filename, int32_t line,
                  const void* text) {
  if (level > DEBUG || level < 0) {
    text = "Bad level pointer passed to biSendLogRpc";
    level = FATAL;  // Assume the worst.
  }
  std::string message = kLevelNames[level];
  message.append(": ");
  message.append(static_cast<const char*>(filename));
  message.append(":");
  message.append(std::to_string(line));
  message.append(" ");
  message.append(static_cast<const char*>(text));
  message.append("\n");

  if (!sealed::wasm::global_server) {
    fputs(message.c_str(), stdout);
  } else if (level == DEBUG) {
    fputs(message.c_str(), stderr);
  } else {
    sealed::wasm::global_server->SendLogRpc(message);
  }

  if (level == FATAL) {
    // Need to flush the stdout and stderr fd before exiting so that the
    // outgoing data envelope is not lost.
    fclose(stdout);
    fclose(stderr);
    exit(1);
  }
}
