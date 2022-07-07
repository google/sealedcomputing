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

#include <cstdlib>
#include <memory>
#include <vector>

#include "third_party/sealedcomputing/wasm3/base.h"
#include "third_party/sealedcomputing/wasm3/builtin/builtin_wasm.h"
#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/enforcer/builtin_impl.h"
#include "third_party/sealedcomputing/wasm3/enforcer/fd_socket.h"
#include "third_party/sealedcomputing/wasm3/enforcer/fiber_listening_socket.h"
#include "third_party/sealedcomputing/wasm3/enforcer/function_registry.h"
#include "third_party/sealedcomputing/wasm3/enforcer/provisioned_state.h"
#include "third_party/sealedcomputing/wasm3/enforcer/server.h"
#include "third_party/sealedcomputing/wasm3/enforcer/wasm.h"
#include "third_party/sealedcomputing/wasm3/enforcer/wasm_globals.h"
#include "third_party/sealedcomputing/wasm3/keyset_policies/emulated_sealer.h"
#include "third_party/sealedcomputing/wasm3/keyset_policies/p256_sign.h"
#include "third_party/sealedcomputing/wasm3/keyset_policies/public_key_sign.h"
#include "third_party/sealedcomputing/wasm3/keyset_policies/public_key_verify.h"
#include "third_party/sealedcomputing/wasm3/logging.h"
#include "third_party/sealedcomputing/wasm3/status.h"
#include "third_party/wasm3/source/wasm3.h"

namespace sealed {
namespace wasm {

bool global_serving = false;

Server* global_server = nullptr;

SecretByteString* global_decrypt_with_group_key_ctx = nullptr;
ByteString* global_encrypt_with_group_key_ctx = nullptr;

}  // namespace wasm
}  // namespace sealed

m3ApiRawFunction(biPrintln_wrapper) {
  m3ApiGetArgMem(const void*, text);
  SC_CHECK(sealed::wasm::MemCheckCstr(text));
  biPrintln(text);
  m3ApiSuccess();
}

void biPrintln(const void* text) {
  if (!sealed::wasm::global_serving) {
    puts(static_cast<const char*>(text));
  } else {
    biSendLogRpc(INFO, __FILE__, __LINE__, text);
  }
}

m3ApiRawFunction(biSendTransactionalRpc_wrapper) {
  m3ApiReturnType(int32_t);
  m3ApiGetArgMem(const void*, service_name);
  m3ApiGetArgMem(const void*, method_name);
  m3ApiGetArgMem(const void*, request_buf);
  m3ApiGetArg(int32_t, request_len);
  SC_CHECK(sealed::wasm::MemCheckCstr(service_name));
  SC_CHECK(sealed::wasm::MemCheckCstr(method_name));
  SC_CHECK(sealed::wasm::MemCheckRange(request_buf, request_len));
  int32_t result = biSendTransactionalRpc(service_name, method_name,
                                          request_buf, request_len);
  m3ApiReturn(result);
}

int32_t biSendTransactionalRpc(const void* service_name,
                               const void* method_name, const void* request_buf,
                               int32_t request_len) {
  return 0;
}

m3ApiRawFunction(biSendRpc_wrapper) {
  m3ApiReturnType(int32_t);
  m3ApiGetArgMem(const void*, service_name);
  m3ApiGetArgMem(const void*, method_name);
  m3ApiGetArgMem(const void*, request_buf);
  m3ApiGetArg(int32_t, request_len);
  m3ApiGetArgMem(const void*, request_secret_buf);
  m3ApiGetArg(int32_t, request_secret_len);
  m3ApiGetArg(int32_t, deadline);
  m3ApiGetArgMem(void*, status_code);
  m3ApiGetArgMem(void*, status_message_len);
  m3ApiGetArgMem(void*, response_secret_len);
  SC_CHECK(sealed::wasm::MemCheckCstr(service_name));
  SC_CHECK(sealed::wasm::MemCheckCstr(method_name));
  SC_CHECK(sealed::wasm::MemCheckRange(request_buf, request_len));
  SC_CHECK(sealed::wasm::MemCheckRange(request_secret_buf, request_secret_len));
  SC_CHECK(sealed::wasm::MemCheckRange(status_code, sizeof(uint32_t)));
  SC_CHECK(sealed::wasm::MemCheckRange(status_message_len, sizeof(uint32_t)));
  SC_CHECK(sealed::wasm::MemCheckRange(response_secret_len, sizeof(uint32_t)));
  int32_t result =
      biSendRpc(service_name, method_name, request_buf, request_len,
                request_secret_buf, request_secret_len, deadline, status_code,
                status_message_len, response_secret_len);
  m3ApiReturn(result);
}

int32_t biSendRpc(const void* service_name, const void* method_name,
                  const void* request_buf, int32_t request_len,
                  const void* request_secret_buf, int32_t request_secret_len,
                  int32_t deadline, void* status_code, void* status_message_len,
                  void* response_secret_len) {
  // TODO: implement deadline.
  return sealed::wasm::global_server->SendRpcFromWasm(
      static_cast<const char*>(service_name),
      static_cast<const char*>(method_name),
      std::string(static_cast<const char*>(request_buf), request_len),
      sealed::wasm::SecretByteString(request_secret_buf, request_secret_len),
      static_cast<uint32_t*>(status_code),
      static_cast<uint32_t*>(status_message_len),
      static_cast<uint32_t*>(response_secret_len));
}

m3ApiRawFunction(biGetRequest_wrapper) {
  m3ApiGetArgMem(void*, request_buf);
  m3ApiGetArg(int32_t, request_len);
  SC_CHECK(sealed::wasm::MemCheckRange(request_buf, request_len));
  biGetRequest(request_buf, request_len);
  m3ApiSuccess();
}

void biGetRequest(void* request_buf, int32_t request_len) {
  memcpy(request_buf, sealed::wasm::global_server->GetCurrentRequest().data(),
         sealed::wasm::global_server->GetCurrentRequest().size());
}

m3ApiRawFunction(biGetRequestSecret_wrapper) {
  m3ApiGetArgMem(void*, request_buf);
  m3ApiGetArg(int32_t, request_len);
  SC_CHECK(sealed::wasm::MemCheckRange(request_buf, request_len));
  biGetRequestSecret(request_buf, request_len);
  m3ApiSuccess();
}

void biGetRequestSecret(void* request_buf, int32_t request_len) {
  SC_CHECK(static_cast<uint32_t>(request_len) ==
           sealed::wasm::global_server->GetCurrentRequestSecret().size());
  memcpy(request_buf,
         sealed::wasm::global_server->GetCurrentRequestSecret().data(),
         sealed::wasm::global_server->GetCurrentRequestSecret().size());
}

m3ApiRawFunction(biGetRequestSecretLength_wrapper) {
  m3ApiReturnType(int32_t);
  int32_t result = biGetRequestSecretLength();
  m3ApiReturn(result);
}

int32_t biGetRequestSecretLength() {
  return sealed::wasm::global_server->GetCurrentRequestSecret().size();
}

m3ApiRawFunction(biSetResponse_wrapper) {
  m3ApiGetArgMem(const void*, response_buf);
  m3ApiGetArg(int32_t, response_len);
  SC_CHECK(sealed::wasm::MemCheckRange(response_buf, response_len));
  biSetResponse(response_buf, response_len);
  m3ApiSuccess();
}

void biSetResponse(const void* response_buf, int32_t response_len) {
  sealed::wasm::global_server->SetCurrentResponse(
      std::string(static_cast<const char*>(response_buf), response_len));
}

m3ApiRawFunction(biSetResponseSecret_wrapper) {
  m3ApiGetArgMem(const void*, response_buf);
  m3ApiGetArg(int32_t, response_len);
  SC_CHECK(sealed::wasm::MemCheckRange(response_buf, response_len));
  biSetResponseSecret(response_buf, response_len);
  m3ApiSuccess();
}

void biSetResponseSecret(const void* response_buf, int32_t response_len) {
  sealed::wasm::global_server->SetCurrentResponseSecret(
      sealed::wasm::SecretByteString(response_buf, response_len));
}

m3ApiRawFunction(biSetResponseStatus_wrapper) {
  m3ApiGetArg(int32_t, status_code);
  m3ApiGetArgMem(const void*, status_message);
  SC_CHECK(sealed::wasm::MemCheckCstr(status_message));
  biSetResponseStatus(status_code, status_message);
  m3ApiSuccess();
}

void biSetResponseStatus(int32_t status_code, const void* status_message) {
  SC_CHECK(status_code >= 0);
  SC_CHECK(status_code <= sealed::wasm::StatusCode::kLast);
  sealed::wasm::global_server->SetCurrentResponseStatus(
      sealed::wasm::Status(static_cast<sealed::wasm::StatusCode>(status_code),
                           static_cast<const char*>(status_message)));
}

m3ApiRawFunction(biRegisterRpcHandler_wrapper) {
  m3ApiGetArgMem(const void*, service_name);
  SC_CHECK(sealed::wasm::MemCheckCstr(service_name));
  m3ApiGetArgMem(const void*, method_name);
  SC_CHECK(sealed::wasm::MemCheckCstr(method_name));
  // We don't use the function pointer when called from wasm bytecode.
  m3ApiGetArgMem(void*, function_pointer);
  (void)function_pointer;
  biRegisterRpcHandler(service_name, method_name, nullptr);
  m3ApiSuccess();
}

void biRegisterRpcHandler(const void* service_name, const void* method_name,
                          void* function_pointer) {
  ::sealed::wasm::GetGlobalFunctionRegistry()->RegisterRpcHandler(
      static_cast<const char*>(service_name),
      static_cast<const char*>(method_name),
      reinterpret_cast<int (*)(int32_t, int32_t)>(function_pointer));
}

m3ApiRawFunction(biServe_wrapper) {
  biServe();
  m3ApiSuccess();
}

void biServe(void) {
  sealed::wasm::global_serving = true;
  auto provisioned_state = std::make_unique<sealed::wasm::ProvisionedState>();
  // TODO(sidtelang): have SocketInternal be a standalone interface (as opposed
  // to extending the Socket interface) and have FdSocket implement the
  // SocketInternal interface only.
  auto in_socket = std::unique_ptr<sealed::wasm::SocketInternal>(
      std::make_unique<sealed::wasm::FdSocket>(
          /*peer=*/"", /*self=*/"",
          /*socket_id=*/"", STDIN_FILENO, /*out_fd=*/-1)
          .release());
  auto out_socket = std::unique_ptr<sealed::wasm::SocketInternal>(
      std::make_unique<sealed::wasm::FdSocket>(
          /*peer=*/"", /*self=*/"",
          /*socket_id=*/"", /*in_fd=*/-1, STDOUT_FILENO)
          .release());
  auto err_socket = std::unique_ptr<sealed::wasm::Socket>(
      std::make_unique<sealed::wasm::FdSocket>(
          /*peer=*/"", /*self=*/"",
          /*socket_id=*/"", /*in_fd=*/-1, STDERR_FILENO)
          .release());
  auto fiber_listening_socket =
      std::make_unique<sealed::wasm::FiberListeningSocket>(
          /*self=*/"", std::move(in_socket), std::move(out_socket),
          std::move(err_socket));
  auto secure_listening_socket =
      std::make_unique<sealed::wasm::SecureListeningSocket>(
          std::unique_ptr<sealed::wasm::ListeningSocketInternal>(
              fiber_listening_socket.release()));

  sealed::wasm::global_server = new sealed::wasm::Server(
      std::move(provisioned_state), std::move(secure_listening_socket));
  sealed::wasm::global_server->Serve();
}

m3ApiRawFunction(biSign_wrapper) {
  m3ApiReturnType(int32_t);
  m3ApiGetArgMem(const void*, challenge_data);
  m3ApiGetArg(int32_t, challenge_length);
  m3ApiGetArgMem(void*, report);
  m3ApiGetArgMem(void*, signature);
  SC_CHECK(sealed::wasm::MemCheckRange(challenge_data, challenge_length))
      << "Bad challenge pointer passed to biSign";
  SC_CHECK(sealed::wasm::MemCheckRange(report,
                                       sealed::wasm::kSerializedReportLength))
      << "Bad report pointer passed to biSign";
  SC_CHECK(
      sealed::wasm::MemCheckRange(signature, sealed::wasm::kSignatureLength))
      << "Bad signature pointer passed to biSign";
  int32_t result = biSign(challenge_data, challenge_length, report, signature);
  m3ApiReturn(result);
}

int biSign(const void* challenge_data, int32_t challenge_length, void* report,
           void* signature) {
  std::string challenge(static_cast<const char*>(challenge_data),
                        challenge_length);
  std::string report_str, signature_str;
  const sealed::wasm::P256Sign* bytecode_signer =
      sealed::wasm::global_server->GetBytecodeSigner();
  if (bytecode_signer == nullptr) {
    // Task is not provisioned yet.
    return 0;
  }
  // TODO: Replace this with the real report when it is ready.
  bytecode_signer->GetVerifyingKey()->Serialize(&report_str);
  if (!bytecode_signer->Sign(report_str + challenge, &signature_str)) {
    return 0;
  }
  SC_CHECK_EQ(report_str.size(), sealed::wasm::kSerializedReportLength);
  SC_CHECK_EQ(signature_str.size(), sealed::wasm::kSignatureLength);
  memcpy(report, report_str.data(), report_str.size());
  memcpy(signature, signature_str.data(), signature_str.size());
  return 1;
}

m3ApiRawFunction(biVerify_wrapper) {
  m3ApiReturnType(int32_t);
  m3ApiGetArgMem(const void*, challenge_data);
  m3ApiGetArg(int32_t, challenge_length);
  m3ApiGetArgMem(const void*, report);
  m3ApiGetArgMem(const void*, signature);
  SC_CHECK(sealed::wasm::MemCheckRange(challenge_data, challenge_length))
      << "Bad message pointer passed to biVerify";
  SC_CHECK(sealed::wasm::MemCheckRange(report,
                                       sealed::wasm::kSerializedReportLength))
      << "Bad signature pointer passed to biVerify";
  SC_CHECK(
      sealed::wasm::MemCheckRange(signature, sealed::wasm::kSignatureLength))
      << "Bad signature pointer passed to biVerify";
  int32_t result =
      biVerify(challenge_data, challenge_length, report, signature);
  m3ApiReturn(result);
}

int biVerify(const void* challenge_data, int32_t challenge_length,
             const void* report, const void* signature) {
  std::string challenge(static_cast<const char*>(challenge_data),
                        challenge_length);
  std::string report_str(static_cast<const char*>(report),
                         sealed::wasm::kSerializedReportLength);
  std::string signature_str(static_cast<const char*>(signature),
                            sealed::wasm::kSignatureLength);
  const sealed::wasm::P256Sign* bytecode_signer =
      sealed::wasm::global_server->GetBytecodeSigner();
  if (bytecode_signer == nullptr) {
    // Task is not provisioned yet.
    return 0;
  }
  return bytecode_signer->GetVerifyingKey()->Verify(report_str + challenge,
                                                    signature_str);
}

m3ApiRawFunction(biGetSendRpcResponse_wrapper) {
  m3ApiGetArgMem(void*, response_buf);
  m3ApiGetArg(int32_t, response_len);
  SC_CHECK(sealed::wasm::MemCheckRange(response_buf, response_len));
  biGetSendRpcResponse(response_buf, response_len);
  m3ApiSuccess();
}

void biGetSendRpcResponse(void* response_buf, int32_t response_len) {
  std::string response = sealed::wasm::global_server->GetSendRpcResponse();
  SC_CHECK_EQ(response.size(), static_cast<uint32_t>(response_len));
  memcpy(response_buf, response.data(), response_len);
}

m3ApiRawFunction(biGetSendRpcResponseSecret_wrapper) {
  m3ApiGetArgMem(void*, response_buf);
  m3ApiGetArg(int32_t, response_len);
  SC_CHECK(sealed::wasm::MemCheckRange(response_buf, response_len));
  biGetSendRpcResponseSecret(response_buf, response_len);
  m3ApiSuccess();
}

void biGetSendRpcResponseSecret(void* response_buf, int32_t response_len) {
  const sealed::wasm::SecretByteString& response_secret =
      sealed::wasm::global_server->GetSendRpcResponseSecret();
  SC_CHECK_EQ(response_secret.size(), static_cast<uint32_t>(response_len));
  memcpy(response_buf, response_secret.data(), response_len);
}

m3ApiRawFunction(biGetSendRpcStatusMessage_wrapper) {
  m3ApiGetArgMem(void*, buf);
  m3ApiGetArg(int32_t, buf_len);
  SC_CHECK(sealed::wasm::MemCheckRange(buf, buf_len));
  biGetSendRpcStatusMessage(buf, buf_len);
  m3ApiSuccess();
}

void biGetSendRpcStatusMessage(void* buf, int32_t buf_len) {
  std::string status_message =
      sealed::wasm::global_server->GetSendRpcStatusMessage();
  SC_CHECK_EQ(status_message.size(), static_cast<uint32_t>(buf_len));
  memcpy(buf, status_message.data(), buf_len);
}

m3ApiRawFunction(biDecryptWithGroupKey_wrapper) {
  m3ApiGetArgMem(const void*, ciphertext);
  m3ApiGetArg(int32_t, ciphertext_len);
  m3ApiGetArgMem(const void*, context_info);
  m3ApiGetArg(int32_t, context_info_len);
  m3ApiGetArgMem(void*, status_code);
  m3ApiGetArgMem(void*, buf_len);
  SC_CHECK(sealed::wasm::MemCheckRange(ciphertext, ciphertext_len));
  SC_CHECK(sealed::wasm::MemCheckRange(context_info, context_info_len));
  SC_CHECK(sealed::wasm::MemCheckRange(status_code, sizeof(uint8_t)));
  SC_CHECK(sealed::wasm::MemCheckRange(buf_len, sizeof(int32_t)));
  biDecryptWithGroupKey(ciphertext, ciphertext_len, context_info,
                        context_info_len, status_code, buf_len);
  m3ApiSuccess();
}

void biDecryptWithGroupKey(const void* ciphertext_buf, int32_t ciphertext_len,
                           const void* context_info_buf,
                           int32_t context_info_len, void* status_code,
                           void* buf_len) {
  std::string ciphertext(static_cast<const char*>(ciphertext_buf),
                         ciphertext_len);
  std::string context_info(static_cast<const char*>(context_info_buf),
                           context_info_len);
  sealed::wasm::StatusOr<sealed::wasm::SecretByteString> plaintext =
      sealed::wasm::global_server->GetGroupDecryptionKey()->Decrypt(
          ciphertext, context_info);
  if (sealed::wasm::global_decrypt_with_group_key_ctx != nullptr) {
    delete sealed::wasm::global_decrypt_with_group_key_ctx;
  }
  if (plaintext.ok()) {
    *(static_cast<sealed::wasm::StatusCode*>(status_code)) = sealed::wasm::kOk;
    *(static_cast<int32_t*>(buf_len)) = plaintext->size();
    sealed::wasm::global_decrypt_with_group_key_ctx =
        new sealed::wasm::SecretByteString(*plaintext);
  } else {
    *(static_cast<sealed::wasm::StatusCode*>(status_code)) = plaintext.code();
    *(static_cast<int32_t*>(buf_len)) = plaintext.message().size();
    sealed::wasm::global_decrypt_with_group_key_ctx =
        new sealed::wasm::SecretByteString(plaintext.message());
  }
}

m3ApiRawFunction(biDecryptWithGroupKeyFinish_wrapper) {
  m3ApiGetArgMem(void*, buf);
  m3ApiGetArg(int32_t, buf_len);
  SC_CHECK(sealed::wasm::MemCheckRange(buf, buf_len));
  biDecryptWithGroupKeyFinish(buf, buf_len);
  m3ApiSuccess();
}

void biDecryptWithGroupKeyFinish(void* buf, int32_t buf_len) {
  SC_CHECK(static_cast<uint32_t>(buf_len) >=
           sealed::wasm::global_decrypt_with_group_key_ctx->size());
  memcpy(buf, sealed::wasm::global_decrypt_with_group_key_ctx->data(),
         sealed::wasm::global_decrypt_with_group_key_ctx->size());
  sealed::wasm::global_decrypt_with_group_key_ctx->clear();
  sealed::wasm::global_decrypt_with_group_key_ctx = nullptr;
}

m3ApiRawFunction(biEncryptWithGroupKey_wrapper) {
  m3ApiReturnType(int32_t);
  m3ApiGetArgMem(const void*, plaintext);
  m3ApiGetArg(int32_t, plaintext_len);
  m3ApiGetArgMem(const void*, context_info);
  m3ApiGetArg(int32_t, context_info_len);
  SC_CHECK(sealed::wasm::MemCheckRange(plaintext, plaintext_len));
  SC_CHECK(sealed::wasm::MemCheckRange(context_info, context_info_len));
  int32_t result = biEncryptWithGroupKey(plaintext, plaintext_len, context_info,
                                         context_info_len);
  m3ApiReturn(result);
}

int32_t biEncryptWithGroupKey(const void* plaintext_buf, int32_t plaintext_len,
                              const void* context_info_buf,
                              int32_t context_info_len) {
  sealed::wasm::SecretByteString plaintext(
      static_cast<const uint8_t*>(plaintext_buf), plaintext_len);
  std::string context_info(static_cast<const char*>(context_info_buf),
                           context_info_len);
  if (sealed::wasm::global_encrypt_with_group_key_ctx != nullptr) {
    delete sealed::wasm::global_encrypt_with_group_key_ctx;
  }
  sealed::wasm::global_encrypt_with_group_key_ctx =
      new sealed::wasm::SecretByteString(
          sealed::wasm::global_server->GetGroupDecryptionKey()
              ->GetPublicKey()
              .Encrypt(plaintext, context_info));
  return sealed::wasm::global_encrypt_with_group_key_ctx->size();
}

m3ApiRawFunction(biEncryptWithGroupKeyFinish_wrapper) {
  m3ApiGetArgMem(void*, buf);
  m3ApiGetArg(int32_t, buf_len);
  SC_CHECK(sealed::wasm::MemCheckRange(buf, buf_len));
  biEncryptWithGroupKeyFinish(buf, buf_len);
  m3ApiSuccess();
}

void biEncryptWithGroupKeyFinish(void* buf, int32_t buf_len) {
  SC_CHECK(static_cast<uint32_t>(buf_len) >=
           sealed::wasm::global_encrypt_with_group_key_ctx->size());
  memcpy(buf, sealed::wasm::global_encrypt_with_group_key_ctx->data(),
         sealed::wasm::global_encrypt_with_group_key_ctx->size());
  sealed::wasm::global_encrypt_with_group_key_ctx->clear();
}
