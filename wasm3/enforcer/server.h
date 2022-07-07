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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_SERVER_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_SERVER_H_

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/enforcer/provisioned_state.h"
#include "third_party/sealedcomputing/wasm3/enforcer/rpc.common.h"
#include "third_party/sealedcomputing/wasm3/enforcer/secure_listening_socket.h"
#include "third_party/sealedcomputing/wasm3/status.h"

namespace sealed {
namespace wasm {

// Serves RPC traffic over a `SecureListeningSocket`.
class Server {
 public:
  Server(std::unique_ptr<ProvisionedState> provisioned_state,
         std::unique_ptr<SecureListeningSocket> secure_listening_socket)
      : provisioned_state_(std::move(provisioned_state)),
        secure_listening_socket_(std::move(secure_listening_socket)) {
    ::sealed::wasm::server::RegisterRpcHandlers();
  }

  // Makes a given RPC to `server_id` over a newly created socket.
  // Returns with the `Status` of the RPC and sets `response` and
  // `response_secret` appropriately.
  Status SendRpc(const Socket::EndpointId& server_id,
                 const std::string& service_name,
                 const std::string& method_name, const std::string& request,
                 const SecretByteString& request_secret, bool require_secure,
                 std::string* response, SecretByteString* response_secret,
                 RpcType type = RpcType::RPC_TYPE_REQUEST);

  // Sends an RPC to the Sealet.
  Status SendSealetRpc(const std::string& method_name,
                       const std::string& request, std::string* response);

  // Uses a stub configured in SealedTaskConfig.
  int32_t SendRpcFromWasm(const std::string& service_name,
                          const std::string& method_name,
                          const std::string& request,
                          const SecretByteString& request_secret,
                          uint32_t* status_code, uint32_t* status_message_len,
                          uint32_t* response_secret_len);

  void SendLogRpc(const std::string& message);

  // Keeps reading incoming RPC messages, processing them, and writing outgoing
  // RPC messages. Returns when the incoming stream is broken.
  void Serve();

  // Process a request to a builtin RPC method, i.e. the RPC handler for this
  // method is directly linked into the policy enforcer binary.
  // Returns true
  // - iff the service and method name in `request_message` map to a registered
  //   handler and if so,
  // - after the handler modifies `response_message` and `response_secret`
  //   appropriately.
  bool ProcessBuiltinRpc(const RpcMessage& request_message,
                         const SecretByteString& request_secret, Socket* socket,
                         RpcMessage* response_message,
                         SecretByteString* response_secret);

  // Process a request to a wasm3 hosted RPC method, i.e. the RPC handler for
  // this method is implemented in WASM bytecode.
  bool ProcessWasm3Request(const RpcMessage& request_message,
                           const SecretByteString& request_secret,
                           Socket* socket, RpcMessage* response_message,
                           SecretByteString* response_secret);

  // The following methods are invoked on the global Server object by
  // WASM builtins. This is required because WASM3 builtins can only be global
  // or static functions.
  std::string GetCurrentRequest() const {
    return current_rpc_context_->request;
  }
  void SetCurrentResponse(const std::string& response) {
    current_rpc_context_->response = response;
  }
  std::string GetSendRpcResponse() const {
    return current_rpc_context_->send_rpc_response;
  }
  const SecretByteString& GetSendRpcResponseSecret() const {
    return current_rpc_context_->send_rpc_response_secret;
  }
  std::string GetSendRpcStatusMessage() const {
    return current_rpc_context_->send_rpc_status.message();
  }
  const P256Sign* GetBytecodeSigner() const {
    return provisioned_state_->GetTaskBytecodeSigner();
  }
  const SecretByteString& GetCurrentRequestSecret() const {
    return current_rpc_context_->request_secret;
  }
  void SetCurrentResponseSecret(const SecretByteString& secret) {
    current_rpc_context_->response_secret = secret;
  }
  void SetCurrentResponseStatus(const Status& status) {
    current_rpc_context_->response_status = status;
  }
  const HybridEncryptionPrivateKey* GetGroupDecryptionKey() const {
    return provisioned_state_->GetGroupEncryptionKey();
  }
  ProvisionedState* GetProvisionedState() { return provisioned_state_.get(); }

  // When we transfer execution from enforcer to WASM bytecode, either by
  // returning from a WASM builtin (i.e. biSendRpc) or calling a WASM3 function
  // (i.e. as in ProcessWasm3Request), we need to store the context of the
  // WASM RPC call so that builtins subsequently called from WASM can access
  // this context.
  struct RpcContext {
    std::string request;
    SecretByteString request_secret;
    std::string response;
    SecretByteString response_secret;
    Status response_status;
    Socket* socket;
    std::string send_rpc_response;
    SecretByteString send_rpc_response_secret;
    Status send_rpc_status;
  };
  RpcContext* GetCurrentRpcContext() { return current_rpc_context_; }
  SecureListeningSocket* GetSecureListeningSocket() {
    return secure_listening_socket_.get();
  }

 private:
  RpcContext* current_rpc_context_;
  std::vector<RpcContext> rpc_contexts_;
  std::unique_ptr<ProvisionedState> provisioned_state_;
  std::unique_ptr<SecureListeningSocket> secure_listening_socket_;
};

extern Server* global_server;

}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_SERVER_H_
