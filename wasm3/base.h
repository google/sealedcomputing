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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_BUILTINS_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_BUILTINS_H_

// This is lightweight C++ wrapper around the low-level builtin APIs which are
// restricted to use only 5 basic datatypes for all parameters.  Be careful not
// to include headers outside std:: because we do not want to bloat the TCB.
// Also minimize use of complex std:: APIs.

#include <cstddef>
#include <cstdint>
#include <string>

#include "third_party/sealedcomputing/wasm3/builtin/builtin_wasm.h"
#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/status.h"

namespace sealed {
namespace wasm {

// For now, the report is just the task's public key.
constexpr uint32_t kSerializedReportLength = 65;
constexpr uint32_t kSignatureLength = 64;
constexpr uint32_t kTinkPrefixLength = 5;

// Requests and responses are encoded in two strings: one secret, the other
// public.  This is used by the code generators.
struct EncodedMessage {
  ByteString public_data;
  SecretByteString secret_data;

  EncodedMessage() {}
  EncodedMessage(ByteString public_data) : public_data(public_data) {}
  EncodedMessage(SecretByteString secret_data) : secret_data(secret_data) {}
  EncodedMessage(ByteString public_data, SecretByteString secret_data)
      : public_data(public_data), secret_data(secret_data) {}

  // Conversions
  operator ByteString() const { return public_data; }
  operator SecretByteString() const { return secret_data; }
};

inline Status Quote(const std::string& challenge,
                    std::string* serialized_report, std::string* signature) {
  // TODO(b/177650010): populate serialized report. This is a certificate for
  // the task public key binding it to task identifiers: code measurements
  // for the enforcer, bytecode and task config.
  // For now, the report contains only the task's public key.
  serialized_report->resize(kSerializedReportLength);
  signature->resize(kSignatureLength);
  if (!biSign(challenge.data(), challenge.size(), serialized_report->data(),
              signature->data())) {
    return Status(kFailedPrecondition,
                  "task signing key not available, task likely unprovisioned "
                  "or not started");
  }
  return Status();
}

inline bool VerifyQuote(const std::string& challenge,
                        const std::string& serialized_report,
                        const std::string& signature) {
  return biVerify(challenge.data(), challenge.size(), serialized_report.data(),
                  signature.data());
}

// Print a line of text to stdout for now.  In the future, this will log via
// Log(INFO) somehow.
inline void Println(const std::string& message) { biPrintln(message.c_str()); }

// Register an RPC handler.  Call this for each RPC served before calling Serve.
inline void RegisterRpcHandler(const std::string& service_name,
                               const std::string& method_name,
                               int (*rpc_handler)(int32_t, int32_t)) {
  biRegisterRpcHandler(service_name.c_str(), method_name.c_str(),
                       reinterpret_cast<void*>(rpc_handler));
}

// Start serving.  The Enforcer already knows what the service is.
inline void Serve() { biServe(); }

// Send an RPC to |service_name|.|method_name|;  Under the hood this does t-of-n
// threshold RPCs to trusted servers and continues retrying forever.  RPCs are
// transactional.  Return |response_length| rather than the response, since the
// bytecode must allocate the memory.
inline std::string SendTransactionalRpc(const std::string& service_name,
                                        const std::string& method_name,
                                        const std::string& request) {
  int32_t response_len =
      biSendTransactionalRpc(service_name.c_str(), method_name.c_str(),
                             request.data(), request.size());
  std::string response(response_len, '\0');
  biGetSendRpcResponse(response.data(), response_len);
  return response;
}

// Send an traditional RPC to |service_name|.|method_name|.  Deadline is in
// micro-seconds, so 1,000,000 means 1 second.  A deadline of 0 means no
// deadline.
inline Status SendRpc(const std::string& service_name,
                      const std::string& method_name,
                      const EncodedMessage& request, uint32_t deadline,
                      EncodedMessage* response) {
  int32_t status_code;
  int32_t status_message_len;
  int32_t response_secret_len = 0;
  int32_t response_len = biSendRpc(
      service_name.c_str(), method_name.c_str(), request.public_data.data(),
      request.public_data.size(), request.secret_data.data(),
      request.secret_data.size(), deadline, &status_code, &status_message_len,
      &response_secret_len);
  response->public_data = ByteString(response_len);
  biGetSendRpcResponse(response->public_data.data(), response_len);
  response->secret_data = SecretByteString(response_secret_len);
  biGetSendRpcResponseSecret(response->secret_data.data(), response_secret_len);
  if (status_code == kOk) {
    return Status();
  }
  std::string status_message;
  status_message.resize(status_message_len);
  biGetSendRpcStatusMessage(status_message.data(), status_message_len);
  return Status(static_cast<StatusCode>(status_code), status_message);
}

// Send an traditional RPC to |service_name|.|method_name|.  Deadline is in
// micro-seconds, so 1,000,000 means 1 second.  A deadline of 0 means no
// deadline.
inline Status SendRpc(const std::string& service_name,
                      const std::string& method_name, const ByteString& request,
                      const SecretByteString& request_secret, uint32_t deadline,
                      ByteString* response, SecretByteString* response_secret) {
  EncodedMessage encoded_response;
  auto result = SendRpc(service_name, method_name,
                        EncodedMessage(request, request_secret), deadline,
                        &encoded_response);
  if (result.ok()) {
    *response = encoded_response.public_data;
    *response_secret = encoded_response.secret_data;
  }
  return result;
}

inline void SetResponse(const ByteString& response) {
  biSetResponse(response.data(), response.size());
}

inline void SetResponseSecret(const SecretByteString& secret) {
  biSetResponseSecret(secret.data(), secret.size());
}

inline void SetResponse(const SecretByteString& response) {
  SetResponseSecret(response);
}

inline void SetResponse(const EncodedMessage& response) {
  SetResponse(response.public_data);
  SetResponseSecret(response.secret_data);
}

inline void SetResponseStatus(const Status& status) {
  biSetResponseStatus(status.code(), status.message().c_str());
}

inline SecretByteString GetRequestSecret() {
  int32_t request_secret_length = biGetRequestSecretLength();
  SecretByteString request_secret(request_secret_length);
  biGetRequestSecret(&request_secret[0], request_secret.size());
  return request_secret;
}

inline StatusOr<SecretByteString> DecryptWithGroupKey(ByteString ciphertext,
                                                      ByteString context_info) {
  StatusCode status_code;
  int32_t response_len;
  biDecryptWithGroupKey(ciphertext.data(), ciphertext.size(),
                        context_info.data(), context_info.size(), &status_code,
                        &response_len);
  if (status_code == kOk) {
    SecretByteString plaintext(response_len);
    biDecryptWithGroupKeyFinish(plaintext.data(), plaintext.size());
    return plaintext;
  } else {
    ByteString status_message(response_len);
    biDecryptWithGroupKeyFinish(status_message.data(), status_message.size());
    return Status(status_code, status_message.string());
  }
}

inline ByteString EncryptWithGroupKey(const SecretByteString& plaintext,
                                      const ByteString& context_info) {
  int32_t response_len =
      biEncryptWithGroupKey(plaintext.data(), plaintext.size(),
                            context_info.data(), context_info.size());
  ByteString response(response_len);
  biEncryptWithGroupKeyFinish(response.data(), response.size());
  return response;
}

// Cleanse secret data.
inline void Cleanse(void* data, size_t len) {
  // The compiler MUST perform writes to RAM through volatile pointers.  This
  // keeps the optimizer from deleting this code.
  volatile char* p = static_cast<char*>(data);
  while (len != 0) {
    *p++ = 0;
    len--;
  }
}

}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_BUILTINS_H_
