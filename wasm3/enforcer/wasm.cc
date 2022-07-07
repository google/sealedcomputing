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

#include "third_party/sealedcomputing/wasm3/enforcer/wasm.h"

#include <cstdint>
#include <cstdio>
#include <string>

#include "third_party/sealedcomputing/wasm3/builtin/builtin_wasm.h"
#include "third_party/sealedcomputing/wasm3/enforcer/builtin_impl.h"
#include "third_party/wasm3/source/m3_env.h"
#include "third_party/wasm3/source/wasm3.h"

namespace sealed {
namespace wasm {
namespace {

IM3Memory global_mem = nullptr;
IM3Runtime global_runtime = nullptr;

#define LinkBuiltin(module, name, signature) \
  LinkBuiltinRaw(module, #name, signature, &name##_wrapper)

// Link a builtin function.
void LinkBuiltinRaw(IM3Module module, const char* name, const char* signature,
                    M3RawCall func_ptr) {
  // m3_LinkRawFunction returns a failure message if no module calls the
  // function, making its return M3Result return value useless.  It is always
  // ignored by the caller.
  m3_LinkRawFunction(module, "*", name, signature, func_ptr);
}

// Link builtin functions.  The signature format is:
//
//     v =  void, only used in return types for functions not returning values.
//     * = void* or const void*
//     i = int32_t
//     I = int64_t
//     f = float
//     F = double
// For example: a function `foo` with the following signature:
//     void foo (int32_t, void*, double);
// has the following signature format string: "v(i*F)".
void LinkBuiltinFunctions(IM3Module module) {
  LinkBuiltin(module, biPrintln, "v(*");
  LinkBuiltin(module, biSign, "i(*i**)");
  LinkBuiltin(module, biVerify, "i(*i**)");
  LinkBuiltin(module, biPanic, "v(*i*");
  LinkBuiltin(module, biSendRpc, "i(***i*ii***)");
  LinkBuiltin(module, biSendTransactionalRpc, "i(***i)");
  LinkBuiltin(module, biSendLogRpc, "v(i*i*)");
  LinkBuiltin(module, biRegisterRpcHandler, "v(***)");
  LinkBuiltin(module, biServe, "v()");
  LinkBuiltin(module, biAesKeyFromBin, "I(*)");
  LinkBuiltin(module, biAesGcmKeyFromBin, "I(*)");
  LinkBuiltin(module, biEncryptAesBlock, "v(I**)");
  LinkBuiltin(module, biDecryptAesBlock, "v(I**)");
  LinkBuiltin(module, biAesGcmEncrypt, "v(I**i*i**");
  LinkBuiltin(module, biAesGcmDecrypt, "v(I**i*i**");
  LinkBuiltin(module, biDestroyAesGcmKey, "v(I)");
  LinkBuiltin(module, biSha256, "v(*i*");
  LinkBuiltin(module, biSha256init, "I()");
  LinkBuiltin(module, biSha256update, "v(I*i)");
  LinkBuiltin(module, biSha256final, "v(I*)");
  LinkBuiltin(module, biHmacSha256, "v(*i*i*)");
  LinkBuiltin(module, biHmacSha256init, "I(*i)");
  LinkBuiltin(module, biHmacSha256update, "v(I*i)");
  LinkBuiltin(module, biHmacSha256final, "v(I*)");
  LinkBuiltin(module, biGetRequest, "v(*i)");
  LinkBuiltin(module, biGetRequestSecret, "v(*i)");
  LinkBuiltin(module, biGetRequestSecretLength, "i()");
  LinkBuiltin(module, biSetResponse, "v(*i)");
  LinkBuiltin(module, biSetResponseSecret, "v(*i)");
  LinkBuiltin(module, biSetResponseStatus, "v(i*)");
  LinkBuiltin(module, biGetSendRpcResponse, "v(*i)");
  LinkBuiltin(module, biGetSendRpcResponseSecret, "v(*i)");
  LinkBuiltin(module, biGetSendRpcStatusMessage, "v(*i)");
  LinkBuiltin(module, biDecryptWithGroupKey, "v(*i*i**)");
  LinkBuiltin(module, biDecryptWithGroupKeyFinish, "v(*i)");
  LinkBuiltin(module, biEncryptWithGroupKey, "i(*i*i)");
  LinkBuiltin(module, biEncryptWithGroupKeyFinish, "v(*i)");
  LinkBuiltin(module, biRandBytes, "v(*i)");
  LinkBuiltin(module, biGenP256PrivateKey, "I()");
  LinkBuiltin(module, biP256PublicKeyFromPrivateKey, "I(I)");
  LinkBuiltin(module, biP256PrivateKeyFromBin, "I(*)");
  LinkBuiltin(module, biP256PrivateKeyToBin, "v(I*)");
  LinkBuiltin(module, biP256EcdsaSign, "I(I*i)");
  LinkBuiltin(module, biEcdsaSigToBin, "v(I*)");
  LinkBuiltin(module, biP256PublicKeyToBin, "v(I*)");
  LinkBuiltin(module, biDestroyP256PublicKey, "v(I)");
  LinkBuiltin(module, biDestroyEcdsaSig, "v(I)");
  LinkBuiltin(module, biDestroyP256PrivateKey, "v(I)");
  LinkBuiltin(module, biP256PublicKeyFromBin, "I(*)");
  LinkBuiltin(module, biEcdsaSigFromBin, "I(*)");
  LinkBuiltin(module, biP256EcdsaVerify, "i(I*iI)");
}

}  // namespace

void PrintWasm3Error(const std::string& message) {
  M3ErrorInfo info;
  IM3Runtime runtime = sealed::wasm::global_runtime;
  m3_GetErrorInfo(runtime, &info);
  const char* file = info.file != nullptr ? info.file : "(null)";
  fprintf(stderr, "WASM3 error in file %s, line %u: \"%s.\" info: \"%s\".\n",
          file, info.line, message.c_str(), info.message);
}

// Run the wasm3 interpreter.  Return an error message on failure, otherwise
// return the M3Result message of calling main in the bytecode.  This is nullptr
// on success.
Status InitWasm(const std::string& in_bytes) {
  IM3Environment env = m3_NewEnvironment();
  if (env == nullptr) {
    std::string message = "Unable to create wasm3 environment";
    PrintWasm3Error(message);
    return Status(StatusCode::kInternal, message);
  }
  global_runtime = m3_NewRuntime(env, /* stack size */ 64 * 1024, nullptr);
  if (global_runtime == nullptr) {
    std::string message = "Unable to create wasm3 runtime";
    PrintWasm3Error(message);
    return Status(StatusCode::kInternal, message);
  }
  IM3Module module = nullptr;
  M3Result result = m3_ParseModule(
      env, &module, reinterpret_cast<const uint8_t*>(in_bytes.data()),
      in_bytes.size());
  if (result != nullptr) {
    std::string message = "Unable to parse module: ";
    message += result;
    PrintWasm3Error(message);
    return Status(StatusCode::kInvalidArgument, message);
  }
  result = m3_LoadModule(global_runtime, module);
  if (result != nullptr) {
    std::string message = "Unable to load wasm module: ";
    message += result;
    PrintWasm3Error(message);
    return Status(StatusCode::kInvalidArgument, result);
  }
  LinkBuiltinFunctions(module);
  global_mem = &global_runtime->memory;
  return Status();
}

Status RunWasmMain() {
  if (global_runtime == nullptr) {
    return Status(StatusCode::kFailedPrecondition,
                  "called RunWasmMain before calling InitWasm");
  }
  IM3Function main_func;
  M3Result result = m3_FindFunction(&main_func, global_runtime, "main");
  if (result != nullptr) {
    std::string message = "Unable to find function main: ";
    message += result;
    PrintWasm3Error(message);
    return Status(StatusCode::kInvalidArgument, message);
  }
  result = m3_CallV(main_func, 1, "enforcer");
  if (result != nullptr) {
    std::string message = "Call to main function failed: ";
    message += result;
    PrintWasm3Error(message);
    return Status(StatusCode::kInvalidArgument, message);
  }
  int retval;
  result = m3_GetResultsV(main_func, &retval);
  if (result != nullptr) {
    std::string message = "Unable to get value returned by main: ";
    message += result;
    PrintWasm3Error(message);
    return Status(StatusCode::kInternal, message);
  }
  return Status();
}

bool CallWasmRpc(const std::string& name, const std::string& request,
                 const SecretByteString& request_secret) {
  std::string full_name = name + "_RPC";
  IM3Function fn;
  M3Result res = m3_FindFunction(&fn, global_runtime, full_name.c_str());
  if (res != nullptr) {
    PrintWasm3Error(std::string("Error looking up ") + full_name + ": " + res);
    return false;
  }
  // The return value will be removed in the future.  No need to check it.
  res = m3_CallV(fn, static_cast<int32_t>(request.size()),
                 static_cast<int32_t>(request_secret.size()));
  if (res != nullptr) {
    PrintWasm3Error(std::string("Error calling ") + full_name + ": " + res);
    return false;
  }
  return true;
}

bool MemCheckRange(const void* ptr, uint32_t len) {
  M3MemoryHeader* mem = global_mem->mallocated;
  const uint8_t* range_start = static_cast<const uint8_t*>(ptr);
  const uint8_t* range_end = range_start + len;
  uint8_t* mem_start = reinterpret_cast<uint8_t*>(mem + 1);
  void* mem_end = static_cast<uint8_t*>(mem_start) + mem->length;
  return range_start >= mem_start && range_end <= mem_end &&
         range_start <= range_end;
}

bool MemCheckCstr(const void* text) {
  M3MemoryHeader* mem = global_mem->mallocated;
  const uint8_t* p = static_cast<const uint8_t*>(text);
  uint8_t* mem_start = reinterpret_cast<uint8_t*>(mem + 1);
  void* mem_end = static_cast<uint8_t*>(mem_start) + mem->length;
  if (p < mem_start || p >= mem_end) {
    return false;
  }
  while (*p != '\0') {
    p++;
    if (p == mem_end) {
      return false;
    }
  }
  return true;
}

}  // namespace wasm
}  // namespace sealed
