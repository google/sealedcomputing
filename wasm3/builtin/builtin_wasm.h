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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_BUILTIN_BUILTIN_WASM_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_BUILTIN_BUILTIN_WASM_H_

// The Wasm3 interpreter lets us link to C++ functions, but apparently they
// cannot be in namespaces (at least that didn't work for me).  So, use the "bi"
// prefix, like we do in large C programs, to avoid collisions in the global
// scope.  Builtin functions have very limited types for parameters and return
// types: int32, int64, float, double, void*, and const void*.

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#if defined(__EMSCRIPTEN__)
#define WASM_EXPORT __attribute__((used)) __attribute__((visibility("default")))
#else
#define WASM_EXPORT
#endif

// Sign using task signing key.
int biSign(const void* challenge_data, int32_t challenge_length, void* report,
           void* signature);

// Verify the signature using the task verifying key.
int biVerify(const void* challenge_data, int32_t challenge_length,
             const void* report, const void* signature);

// Print to stdout if not serving, and call Log(INFO) if serving.
void biPrintln(const void* text);

// Send an RPC to the method identified by |service_name| and |method_name|.
// Policy enforcer config includes a mapping from |service_name| to the
// identity of the server providing |service_name|.
// This blocks until the RPC succeeds, or the deadline is exceeded.  A status
// code is returned, and if not kOk, a status message is returend.  Sealed
// storage is not allowed to be mutated by this non-transactional RPC handlers,
// and only non-transactional RPCs can be sent in response to a
// non-transactional RPC.  Return the response length.
// Note: |service_name| and |method_name| are c-style strings that must be
//       null terminated.
int32_t biSendRpc(const void* service_name, const void* method_name,
                  const void* request_buf, int32_t request_len,
                  const void* request_secret_buf, int32_t request_secret_len,
                  int32_t deadline, void* status_code, void* status_message_len,
                  void* response_secret_len);

// Read the status message if the status code is not kOk.
void biGetSendRpcStatusMessage(void* buf, int32_t buf_len);

// Send a transactional RPC to the method identified by
// |service_name|.|method_name|.  Under the hood, the service providers we trust
// are looked up and we do a t-of-n threshold RPC with them, where t can be 1.
// This blocks until the RPC succeeds, retrying forever.  Sealed storage can be
// modified by a transactional RPC.  Other sealed nodes can be asked to
// authorize the request if needed to satisfy Sealed Storage requirements, and a
// transactional RPC handler may call either transactional or non-transactional
// RPCs.  A deadline can be set on transactional RPCs, and the bytecode
// interpreter is reset if the deadline is exceeded.  Transactional RPCs which
// mutate sealed storage are slow, since a threshold of Sealed Storage nodes
// must first have consensus on the next transaction to execute, and that
// consensus must be persisted to Eidetic before continuing.  Then the
// transaction happens, and again Sealed Storage blocks on mutation writes until
// Eidetic persists the new state.
//
// Note: transactional RPCs are simpler to use, and we aim to support
// 345-compliant levels of availability for them.  RPCs that matter should be
// transactional, with few exceptions.  However, they are slow.
//
// Return the response length.
int32_t biSendTransactionalRpc(const void* service_name,
                               const void* method_name, const void* request_buf,
                               int32_t request_len);

// Copy the response to |response_buf|.
void biGetSendRpcResponse(void* response_buf, int32_t response_len);

// Copy the response secret to |response_buf|.
void biGetSendRpcResponseSecret(void* response_buf, int32_t response_len);

// Copy a request blob into the VM.  This is called by auto-generated RPC code
// inside the VM.
void biGetRequest(void* request_buf, int32_t request_len);

// Copy the request secret blob into the VM.  This is called by auto-generated
// RPC code inside the VM.
int32_t biGetRequestSecretLength();
void biGetRequestSecret(void* request_buf, int32_t request_len);

// Set a response to be sent on stdout by the Server when the WASM RPC method
// returns from the bytecode.
// This is called by auto-generated RPC code inside the VM.
void biSetResponse(const void* response_buf, int32_t response_len);

// Put the response secret to be encrypted and sent on stdout by the Server when
// the WASM RPC method returns from the bytecode. This is called by
// auto-generated RPC code inside the VM.
void biSetResponseSecret(const void* response_buf, int32_t response_len);

// Set a non-OK status in the response to a WASM RPC method.
// This is called by auto-generated code inside the VM.
void biSetResponseStatus(int32_t status_code, const void* status_message);

// Register an RPC handler.
void biRegisterRpcHandler(const void* service_name, const void* method_name,
                          void* function_pointer);

// Start serving requests.  This never returns.
void biServe(void);

// Decrypt using group hybrid encryption private key.
// After return, if |status_code| corresponds to kOk then |buf_len| is the
// length of the plaintext message. Otherwise |buf_len| is the length of the
// status message.
void biDecryptWithGroupKey(const void* ciphertext, int32_t ciphertext_len,
                           const void* context_info, int32_t context_info_len,
                           void* status_code, void* buf_len);

// Writes the result of biDecryptWithGroupKey (plaintext or status message) to
// |buf|.
void biDecryptWithGroupKeyFinish(void* buf, int32_t buf_len);

// Encrypt using group hybrid encryption private key.
// Returns the length of the ciphertext.
int32_t biEncryptWithGroupKey(const void* plaintext, int32_t plaintext_len,
                              const void* context_info,
                              int32_t context_info_len);

// Writes the result of biEncryptWithGroupKey (ciphertext) to |buf|.
void biEncryptWithGroupKeyFinish(void* buf, int32_t buf_len);

// This is the entry point to a client C++ sealed application.
int start(void);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_BUILTIN_BUILTIN_WASM_H_
