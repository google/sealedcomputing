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
#include <iostream>
#include <memory>
#include <string>

#include "base/callback.h"
#include "base/init_google.h"
#include "net/proto2/contrib/parse_proto/parse_text_proto.h"
#include "net/proto2/public/text_format.h"
#include "net/rpc2/contrib/util/smart-service.proto.h"
#include "net/rpc2/contrib/util/smart-stub.h"
#include "security/sealedcomputing/boq/sealet/client/client_endpoint.h"
#include "security/sealedcomputing/boq/sealet/proto/sealet.stubby.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/numbers.h"
#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/enforcer/hybrid_encryption_tink.h"
#include "third_party/sealedcomputing/wasm3/enforcer/provisioning_service.client.h"
#include "third_party/sealedcomputing/wasm3/enforcer/provisioning_service.common.h"
#include "third_party/sealedcomputing/wasm3/examples/e2e_authn/e2e_authn.client.h"
#include "third_party/sealedcomputing/wasm3/examples/e2e_authn/e2e_authn.common.h"
#include "third_party/sealedcomputing/wasm3/socket.h"
#include "third_party/tink/cc/hybrid/hybrid_config.h"
#include "third_party/tink/cc/hybrid_encrypt.h"
#include "util/shell/command-line.h"
#include "util/task/status_macros.h"

namespace sealed::e2e_authn::client {

using ::sealed::sealet::proto::Sealet;
using ::sealed::wasm::ProvisionGroupResponse;
using ::sealed::wasm::ProvisionTaskResponse;
using ::sealed::wasm::SealedGroupConfig;
using ::sealed::wasm::SealedTaskConfig;
using ::sealed::wasm::Socket;
using ::sealed::wasm::StatusCodeToString;
using ::sealed::wasm::StatusOr;

absl::StatusOr<std::string> EncryptToPublicKey(const std::string& public_key,
                                               const std::string& plaintext) {
  ASSIGN_OR_RETURN(auto serialized_tink_public_keyset,
                   wasm::GetTinkPublicKeyset(public_key));
  ASSIGN_OR_RETURN(auto keyset_handle, crypto::tink::KeysetHandle::ReadNoSecret(
                                           serialized_tink_public_keyset));
  RETURN_IF_ERROR(crypto::tink::HybridConfig::Register());
  ASSIGN_OR_RETURN(auto hybrid_encrypt,
                   keyset_handle->GetPrimitive<crypto::tink::HybridEncrypt>());
  return hybrid_encrypt->Encrypt(plaintext, /*context_info=*/"");
}

class ClientTool : public CommandLine {
 public:
  ClientTool() : CommandLine(GetOptions()) {
    RegisterCommand("init", "Establish a connection to the Sealet Borg Task.",
                    NewPermanentCallback(this, &ClientTool::Init));
    RegisterCommand(
        "provision_task",
        "Provision the Sealed Task. Uses a hardcoded SealedTaskConfig. Outputs "
        "the sealed task public key in hex.",
        NewPermanentCallback(this, &ClientTool::ProvisionTask));
    RegisterCommand("provision_job",
                    "Provision the Sealed Job. Stores and outputs the "
                    "resulting sealed job public key in hex.",
                    NewPermanentCallback(this, &ClientTool::ProvisionGroup));
    RegisterCommand("echo",
                    "Call Echo with input string. Outputs the response string.",
                    NewPermanentCallback(this, &ClientTool::CallEcho));
    RegisterCommand("enroll", "Call Enroll with input KF and recovery key.",
                    NewPermanentCallback(this, &ClientTool::CallEnroll));
    RegisterCommand("open",
                    "Call Open with input KF. On successful claim, outputs the "
                    "recovery key and returns an error otherwise.",
                    NewPermanentCallback(this, &ClientTool::CallOpen));
    RegisterCommand("encrypt_to_job",
                    "Encrypts a string to the stored sealed job public key and "
                    "outputs the ciphertext.",
                    NewPermanentCallback(this, &ClientTool::Encrypt));
    RegisterCommand(
        "decrypt_and_echo", "Call DecryptAndEcho with input ciphertext.",
        NewPermanentCallback(this, &ClientTool::CallDecryptAndEcho));
  }

 private:
  static Options GetOptions() {
    Options options;
    options.set_prompt_format("> ");
    return options;
  }

  std::unique_ptr<Sealet> stub_;
  std::unique_ptr<wasm::ClientEndpoint> client_endpoint_;

  std::string task_pubkey_;
  std::string task_wrapped_blob_;

  std::string group_pubkey_;
  std::string group_wrapped_blob_;

  // `arg` is a SmartService text proto.
  int Init(const std::string& arg) {
    auto smart_service_or_status = proto2::contrib::parse_proto::ParseTextProto<
        rpc2::contrib::SmartService>(arg);
    if (!smart_service_or_status.ok()) {
      LOG(ERROR) << "Error parsing SmartService proto: "
                 << smart_service_or_status.status();
      return 1;
    }
    auto stub_or_status = rpc2::contrib::NewSmartStub<Sealet>(
        smart_service_or_status.ValueOrDie());
    if (!stub_or_status.ok()) {
      LOG(ERROR) << "Error reaching Sealet server: " << stub_or_status.status();
      return 1;
    }
    stub_ = std::move(stub_or_status.ValueOrDie());
    client_endpoint_ = wasm::ClientEndpoint::Create(std::move(stub_));
    LOG(INFO) << "Connection to Sealet Borg task established";
    return 0;
  }

  void ProvisionTask(const std::string& arg) {
    SealedTaskConfig task_config = {
        .inbound_rpc_configs =
            {
                {"Echo", false},
                {"Enroll", true},
                {"Open", true},
                {"DecryptAndEcho", false},
            },
        .sealer_type = wasm::SealerType::SEALER_TYPE_TEST,
    };
    std::unique_ptr<Socket> socket =
        client_endpoint_->CreateInsecureSocket(/*peer=*/"");
    StatusOr<ProvisionTaskResponse> response_or =
        wasm::client::ProvisionTask(task_config, socket.get());
    if (!response_or.ok()) {
      LOG(ERROR) << "Error provisioning the sealed task. Code: "
                 << StatusCodeToString(response_or.code())
                 << ", message: " << response_or.message();
      return;
    }
    task_pubkey_ = response_or->task_pubkey;
    task_wrapped_blob_ = response_or->wrapped_blob;
    std::string task_pubkey_hex = wasm::ByteString(task_pubkey_).hex();
    LOG(INFO) << "Sealed Task provisioned. Sealed Task public key: "
              << task_pubkey_hex;
    std::cout << task_pubkey_hex << std::endl;
  }

  int ProvisionGroup(const std::string& arg) {
    if (task_pubkey_.empty()) {
      LOG(ERROR) << "Can not provision the Sealed Job before provisioning the "
                    "Sealed Task";
      return 1;
    }
    SealedGroupConfig group_config = {
        .task_pubkeys = {task_pubkey_},
    };
    std::unique_ptr<Socket> socket =
        client_endpoint_->CreateInsecureSocket(/*peer=*/"");
    StatusOr<ProvisionGroupResponse> response_or =
        wasm::client::ProvisionGroupGenesis({group_config}, socket.get());
    if (!response_or.ok()) {
      LOG(ERROR) << "Error provisioning the sealed job. Code: "
                 << StatusCodeToString(response_or.code())
                 << ", message: " << response_or.message();
      return 1;
    }
    group_pubkey_ = response_or->group_pubkey;
    group_wrapped_blob_ = response_or->wrapped_blob;
    std::string group_pubkey_hex = wasm::ByteString(group_pubkey_).hex();
    LOG(INFO) << "Sealed Job provisioned. Sealed Job public key: "
              << group_pubkey_hex;
    std::cout << group_pubkey_hex << std::endl;
    return 0;
  }

  int CallEcho(const std::string& arg) {
    std::unique_ptr<Socket> socket =
        client_endpoint_->CreateInsecureSocket(task_pubkey_);
    StatusOr<EchoResponse> echo_response = Echo({arg}, socket.get());
    if (!echo_response.ok()) {
      LOG(ERROR) << "Error calling RPC method Echo. Code: "
                 << StatusCodeToString(echo_response.code())
                 << ", message: " << echo_response.message();
      return 1;
    }
    std::string response = echo_response->response;
    LOG(INFO) << "Response: " << response << std::endl;
    std::cout << response << std::endl;
    return 0;
  }

  int CallEnroll(const std::string& arg) {
    std::vector<std::string> args =
        absl::StrSplit(arg, ' ', absl::SkipWhitespace());
    if (args.size() != 4) {
      LOG(ERROR) << "Usage: enroll [id] [kf] [recovery_key] [guesses]";
      return 1;
    }
    const std::string id = args[0];
    const std::string kf = args[1];
    const std::string recovery_key = args[2];
    uint32_t bad_guess_limit = 0;
    if (!absl::SimpleAtoi(args[3], &bad_guess_limit)) {
      LOG(ERROR) << "Error parsing guesses.";
      return 1;
    }

    if (task_pubkey_.empty()) {
      LOG(ERROR) << "Called enroll before provisioning the task";
      return 1;
    }

    auto statusor = client_endpoint_->CreateSecureSocket(task_pubkey_);
    if (!statusor.ok()) {
      LOG(ERROR) << "Error establishing secure session; code: "
                 << StatusCodeToString(statusor.code())
                 << ", message: " << statusor.message();
      return 1;
    }
    std::unique_ptr<Socket> socket = std::move(*statusor);
    StatusOr<EnrollResponse> enroll_response =
        Enroll({id, kf, recovery_key, bad_guess_limit}, socket.get());
    if (!enroll_response.ok()) {
      LOG(ERROR) << "Enroll returned non-OK status; code: "
                 << StatusCodeToString(enroll_response.code())
                 << ", message: " << enroll_response.message();
      return 1;
    }
    LOG(INFO) << "Enroll succeeded";
    return 0;
  }

  int CallOpen(const std::string& arg) {
    std::vector<std::string> args =
        absl::StrSplit(arg, ' ', absl::SkipWhitespace());
    if (args.size() != 2) {
      LOG(ERROR) << "Usage: open [id] [kf]";
      return 1;
    }
    const std::string id = args[0];
    const std::string kf = args[1];

    if (task_pubkey_.empty()) {
      LOG(ERROR) << "Called open before provisioning the task";
      return 1;
    }

    auto statusor = client_endpoint_->CreateSecureSocket(task_pubkey_);
    if (!statusor.ok()) {
      LOG(ERROR) << "Error establishing secure session; code: "
                 << StatusCodeToString(statusor.code())
                 << ", message: " << statusor.message();
      return 1;
    }
    std::unique_ptr<Socket> socket = std::move(*statusor);
    StatusOr<OpenResponse> open_response = Open({id, kf}, socket.get());
    if (!open_response.ok()) {
      LOG(ERROR) << "Open returned non-OK status; code: "
                 << StatusCodeToString(open_response.code())
                 << ", message: " << open_response.message();
      return 1;
    }
    if (!open_response->is_guess_correct) {
      LOG(ERROR) << "Open returned: incorrect guess";
      return 1;
    }
    std::string recovery_key = open_response->recovery_key;
    LOG(INFO) << "Open returned recovery_key: " << recovery_key;
    std::cout << recovery_key << std::endl;
    return 0;
  }

  int Encrypt(const std::string& arg) {
    if (group_pubkey_.empty()) {
      LOG(ERROR) << "Sealed Job public key unavailable. Provision the Sealed "
                    "Job first."
                 << std::endl;
      return 1;
    }
    absl::StatusOr<std::string> ciphertext =
        EncryptToPublicKey(group_pubkey_, arg);
    if (!ciphertext.ok()) {
      LOG(ERROR) << "Encrypting to Sealed Job failed with status: "
                 << ciphertext.status();
      return 1;
    }
    std::string ciphertext_hex = wasm::ByteString(*ciphertext).hex();
    LOG(INFO) << "Ciphertext: " << ciphertext_hex << std::endl;
    std::cout << ciphertext_hex << std::endl;
    return 0;
  }

  int CallDecryptAndEcho(const std::string& arg) {
    StatusOr<wasm::ByteString> ciphertext = wasm::ByteString::Hex(arg);
    if (!ciphertext.ok()) {
      LOG(ERROR) << "Parsing ciphertext failed with error: "
                 << ciphertext.status();
      return 1;
    }
    std::unique_ptr<Socket> socket =
        client_endpoint_->CreateInsecureSocket(task_pubkey_);
    StatusOr<DecryptAndEchoResponse> response =
        DecryptAndEcho({ciphertext->string()}, socket.get());
    if (!response.ok()) {
      LOG(ERROR) << "Error calling DecryptAndEcho: " << response.status();
      return 1;
    }
    LOG(INFO) << "Response: " << response->plaintext;
    std::cout << response->plaintext << std::endl;
    return 0;
  }
};

}  // namespace sealed::e2e_authn::client

int main(int argc, char** argv) {
  InitGoogle(argv[0], &argc, &argv, true);
  sealed::e2e_authn::client::ClientTool client_tool;
  client_tool.Run(argc, argv);
  return 0;
}
