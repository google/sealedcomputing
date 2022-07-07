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

#include "third_party/sealedcomputing/wasm3/enforcer/server.h"

#include <memory>

#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/enforcer/builtin_impl.h"
#include "third_party/sealedcomputing/wasm3/enforcer/function_registry.h"
#include "third_party/sealedcomputing/wasm3/enforcer/provisioning_service.h"
#include "third_party/sealedcomputing/wasm3/enforcer/rpc.common.h"
#include "third_party/sealedcomputing/wasm3/enforcer/status_encode_decode.h"
#include "third_party/sealedcomputing/wasm3/enforcer/wasm.h"
#include "third_party/sealedcomputing/wasm3/logging.h"
#include "third_party/sealedcomputing/wasm3/send_rpc.h"
#include "third_party/sealedcomputing/wasm3/status.h"
#include "third_party/sealedcomputing/wasm3/statusor.h"

namespace sealed {
namespace wasm {

using ::sealed::wasm::StatusOr;

namespace {

void EncodeStatusAndRespond(const Status& status, Socket* bidi_socket,
                            Socket* err_socket) {
  RpcMessage message;
  message.type = RpcType::RPC_TYPE_RESPONSE;
  message.encoded_status = EncodeStatus(status);
  std::string encoded_status = EncodeRpcMessage(message).public_data;
  bidi_socket->Send(encoded_status, /*payload_secret=*/"");
  err_socket->Send(encoded_status, /*payload_secret=*/"");
}

// Invoked for every incoming RPC request. Sends the RPC response (including
// status) on `bidi_socket` and additionally logs errors to `err_socket`.
void Callback(void* uncast_arg, const ByteString& first_message,
              const SecretByteString& first_message_secret, Socket* bidi_socket,
              Socket* err_socket, ListeningSocket* listening_socket) {
  // Cast `uncast_arg` to Server*
  Server* server = static_cast<Server*>(uncast_arg);

  // Parse first_message as RpcMessage
  StatusOr<RpcMessage> incoming_message = DecodeRpcMessage(first_message);
  if (!incoming_message.ok()) {
    EncodeStatusAndRespond(incoming_message.status(), bidi_socket, err_socket);
    return;
  }

  if (incoming_message->type != RpcType::RPC_TYPE_REQUEST) {
    auto status = Status(kInvalidArgument, "got a dangling response");
    EncodeStatusAndRespond(status, bidi_socket, err_socket);
    return;
  }

  RpcMessage outgoing_message;
  SecretByteString outgoing_secret;
  if (!server->ProcessBuiltinRpc(*incoming_message, first_message_secret,
                                 bidi_socket, &outgoing_message,
                                 &outgoing_secret) &&
      !server->ProcessWasm3Request(*incoming_message, first_message_secret,
                                   bidi_socket, &outgoing_message,
                                   &outgoing_secret)) {
    std::string error_message = "No handler registered for RPC method name: ";
    PrintWasm3Error(error_message);
    auto status = Status(kInvalidArgument,
                         error_message.append(incoming_message->method_name));
    EncodeStatusAndRespond(status, bidi_socket, err_socket);
    return;
  }
  bidi_socket->Send(EncodeRpcMessage(outgoing_message), outgoing_secret);
}

}  // namespace

bool Server::ProcessBuiltinRpc(const RpcMessage& request_message,
                               const SecretByteString& request_secret,
                               Socket* socket, RpcMessage* response_message,
                               SecretByteString* response_secret) {
  RpcHandler handler;
  if (!GetGlobalFunctionRegistry()->GetRpcHandler(request_message.service_name,
                                                  request_message.method_name,
                                                  &handler)) {
    return false;
  }
  RpcContext context;
  context.request = request_message.payload;
  context.request_secret = request_secret;
  context.socket = socket;
  rpc_contexts_.push_back(context);
  current_rpc_context_ = rpc_contexts_.data() + rpc_contexts_.size() - 1;
  auto rpc_context_iterator = rpc_contexts_.end() - 1;

  // TODO(sidtelang): remove return value from generated "_RPC" server methods.
  handler(request_message.payload.size(), request_secret.size());

  response_message->type = RpcType::RPC_TYPE_RESPONSE;
  response_message->service_name = request_message.service_name;
  response_message->method_name = request_message.method_name;
  response_message->payload = current_rpc_context_->response;
  response_message->encoded_status =
      EncodeStatus(current_rpc_context_->response_status);
  *response_secret = current_rpc_context_->response_secret;

  rpc_contexts_.erase(rpc_context_iterator);
  current_rpc_context_ = nullptr;
  return true;
}

void Server::Serve() { secure_listening_socket_->Listen(&Callback, this); }

int32_t Server::SendRpcFromWasm(const std::string& service_name,
                                const std::string& method_name,
                                const std::string& request,
                                const SecretByteString& request_secret,
                                uint32_t* status_code,
                                uint32_t* status_message_len,
                                uint32_t* response_secret_len) {
  Socket::EndpointId server_id;
  bool secure = true;
  for (const auto& config :
       provisioned_state_->GetTaskConfig().outbound_rpc_configs) {
    if (config.method_name == method_name) {
      server_id = config.pubkey;
      secure = config.require_secure;
      break;
    }
  }

  std::string response;
  SecretByteString response_secret;
  Status status = SendRpc(server_id, service_name, method_name, request,
                          request_secret, secure, &response, &response_secret);

  current_rpc_context_->send_rpc_response = response;
  current_rpc_context_->send_rpc_response_secret = response_secret;
  current_rpc_context_->send_rpc_status = status;
  *status_code = status.code();
  *status_message_len = status.message().size();
  *response_secret_len = current_rpc_context_->send_rpc_response_secret.size();
  return current_rpc_context_->send_rpc_response.size();
}

Status Server::SendRpc(const Socket::EndpointId& server_id,
                       const std::string& service_name,
                       const std::string& method_name,
                       const std::string& request,
                       const SecretByteString& request_secret,
                       bool require_secure, std::string* response,
                       SecretByteString* response_secret, RpcType type) {
  // Store pointer to current RPC context on stack.
  // The sealed::wasm::SendRpc call below is expected to switch execution to a
  // different fiber while this current fiber is blocked on a response to the
  // outgoing RPC. All fibers share the global Server object, and a fiber switch
  // is expected to change the current_rpc_context_ of this Server object.
  // Therefore, storing current_rpc_context_ on the stack (which is separate for
  // each fiber) allows us to restore it before this function returns back to
  // the calling bytecode/handler.
  RpcContext* current_context = current_rpc_context_;

  std::unique_ptr<Socket> socket;
  SC_ASSIGN_OR_RETURN(socket, secure_listening_socket_->CreateSocket(
                                  server_id, require_secure));
  Status status =
      sealed::wasm::SendRpc(service_name, method_name, request, request_secret,
                            response, response_secret, socket.get(), type);
  current_rpc_context_ = current_context;
  return status;
}

Status Server::SendSealetRpc(const std::string& method_name,
                             const std::string& request,
                             std::string* response) {
  SecretByteString unused;
  return SendRpc(/*server_id=*/"", /*service_name=*/"", method_name, request,
                 /*request_secret=*/"", /*require_secure=*/false, response,
                 &unused, RpcType::RPC_TYPE_SEALET_REQUEST);
}

void Server::SendLogRpc(const std::string& message) {
  RpcMessage request_message;
  request_message.type = RpcType::RPC_TYPE_LOG;
  request_message.payload = message;
  std::unique_ptr<Socket> socket;
  // TODO(sidtelang): create EndpointId value designating hosting sealet
  // as a socket peer, replacing "localhost" value below.
  SC_CHECK_OK_AND_ASSIGN(
      socket, secure_listening_socket_->CreateSocket("localhost", false));
  socket->Send(EncodeRpcMessage(request_message),
               /*payload_secret=*/"");
}

// Process a wasm3 hosted request.
bool Server::ProcessWasm3Request(const RpcMessage& request_message,
                                 const SecretByteString& request_secret,
                                 Socket* socket, RpcMessage* response_message,
                                 SecretByteString* response_secret) {
  // Return false if method name for incoming request is not present in the task
  // config.
  bool secure = true;
  bool method_configured = false;
  for (const auto& config :
       provisioned_state_->GetTaskConfig().inbound_rpc_configs) {
    if (config.method_name == request_message.method_name) {
      method_configured = true;
      secure = config.require_secure;
      break;
    }
  }
  if (!method_configured) {
    return false;
  }

  // If method is configured to require authenticated requests and incoming
  // request is not authenticated, return an error.
  if (secure && !socket->IsSecure()) {
    response_message->type = RpcType::RPC_TYPE_RESPONSE;
    std::string error_message;
    error_message += "Got unauthenticated request to RPC method name " +
                     request_message.method_name +
                     " which requires authenticated RPCs";
    response_message->encoded_status =
        EncodeStatus(Status(kUnauthenticated, error_message));
    return true;
  }

  RpcContext rpc_context;
  rpc_context.request = request_message.payload;
  rpc_context.request_secret = request_secret;
  rpc_context.socket = socket;
  rpc_contexts_.push_back(rpc_context);
  current_rpc_context_ = rpc_contexts_.data() + rpc_contexts_.size() - 1;
  auto rpc_context_iterator = rpc_contexts_.end() - 1;

  if (!CallWasmRpc(request_message.method_name, request_message.payload,
                   request_secret)) {
    return false;
  }

  response_message->type = RpcType::RPC_TYPE_RESPONSE;
  response_message->service_name = request_message.service_name;
  response_message->method_name = request_message.method_name;
  response_message->payload = current_rpc_context_->response;
  response_message->encoded_status =
      EncodeStatus(current_rpc_context_->response_status);
  *response_secret = current_rpc_context_->response_secret;

  rpc_contexts_.erase(rpc_context_iterator);
  current_rpc_context_ = nullptr;
  return true;
}

}  // namespace wasm
}  // namespace sealed
