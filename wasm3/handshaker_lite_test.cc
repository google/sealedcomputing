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
#include <optional>

#include "third_party/sealedcomputing/wasm3/bytestring.h"
#include "third_party/sealedcomputing/wasm3/handshaker.h"
#include "third_party/sealedcomputing/wasm3/keyset_policies/p256_sign.h"
#include "third_party/sealedcomputing/wasm3/logging.h"

namespace sealed {
namespace wasm {
namespace {

using Result = Handshaker::Result;

class HandshakerTest {
 public:
  HandshakerTest() {
    client_sign_ = P256Sign::Create(kHandshakeSigningPurpose);
    client_verify_ = client_sign_->GetVerifyingKey();

    server_sign_ = P256Sign::Create(kHandshakeSigningPurpose);
    server_verify_ = server_sign_->GetVerifyingKey();

    client_ = std::make_unique<ClientHandshaker>(HandshakerOptions{
        .self_signing_key = client_sign_.get(),
        .peer_verifying_key = server_verify_.get(),
    });
    server_ = std::make_unique<ServerHandshaker>(HandshakerOptions{
        .self_signing_key = server_sign_.get(),
        .peer_verifying_key = client_verify_.get(),
    });
  }

  // If breakpoint is not present then runs handshaker till both client and
  // server are in terminal state.
  void RunHandshakeTill(std::optional<Result> breakpoint) {
    std::string incoming_bytes;
    bool client_active = true;
    Handshaker *active_handshaker = client_.get();

    // Run the next step of the handshake using either the client handshaker or
    // the server handshaker.
    while (!Handshaker::IsTerminalResult(client_->GetResult()) ||
           !Handshaker::IsTerminalResult(server_->GetResult())) {
      std::string outgoing_bytes;
      Result result =
          active_handshaker->NextHandshakeStep(incoming_bytes, &outgoing_bytes);

      incoming_bytes = outgoing_bytes;
      outgoing_frames_.push_back(outgoing_bytes);

      client_active = !client_active;
      active_handshaker = client_active
                              ? static_cast<Handshaker *>(client_.get())
                              : static_cast<Handshaker *>(server_.get());

      if (breakpoint.has_value() && result == breakpoint.value()) {
        break;
      }
    }
  }

  void EndToEnd() {
    RunHandshakeTill(std::nullopt);

    SC_CHECK_EQ(client_->GetResult(), Result::COMPLETED);
    SC_CHECK_EQ(server_->GetResult(), Result::COMPLETED);
    SessionSecrets client_secrets = client_->GetSessionSecrets();
    SessionSecrets server_secrets = server_->GetSessionSecrets();
    SC_CHECK_EQ(client_secrets.self_encryption_key,
                server_secrets.peer_encryption_key);
    SC_CHECK_EQ(client_secrets.peer_encryption_key,
                server_secrets.self_encryption_key);
    SC_CHECK_EQ(client_secrets.self_mac_secret, server_secrets.peer_mac_secret);
    SC_CHECK_EQ(client_secrets.peer_mac_secret, server_secrets.self_mac_secret);
  }

 private:
  std::unique_ptr<P256Sign> client_sign_;
  std::unique_ptr<P256Verify> client_verify_;
  std::unique_ptr<ClientHandshaker> client_;
  std::unique_ptr<P256Sign> server_sign_;
  std::unique_ptr<P256Verify> server_verify_;
  std::unique_ptr<ServerHandshaker> server_;
  std::vector<std::string> outgoing_frames_;
};

}  // namespace
}  // namespace wasm
}  // namespace sealed

int main() {
  sealed::wasm::HandshakerTest test;
  test.EndToEnd();
  SC_LOG(INFO) << "PASSED";
  return 0;
}
