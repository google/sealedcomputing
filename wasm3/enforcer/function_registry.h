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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_FUNCTION_REGISTRY_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_FUNCTION_REGISTRY_H_

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace sealed {
namespace wasm {

using RpcHandler = int (*)(int32_t, int32_t);
using RpcServiceInitializer = int (*)();

class ServiceRegistry {
 public:
  ServiceRegistry() {}
  ServiceRegistry(const std::string& service_name)
      : service_name_(service_name) {}
  // Register an RPC handler for this service.  Throws memory exception on
  // failure in Linux, aborts in UEFI enclave.
  void RegisterRpc(const std::string& method_name, RpcHandler handler) {
    handler_map_[method_name] = handler;
  }
  // Get the RPC handler for this service.
  RpcHandler GetHandler(std::string method_name) {
    auto it = handler_map_.find(method_name);
    if (it == handler_map_.end()) {
      return nullptr;
    }
    return it->second;
  }

 private:
  std::unordered_map<std::string, RpcHandler> handler_map_;
  std::string service_name_;
};

// Provides methods to register sealed RPC handlers (called for each RPC
// request) and service initializers (called once during server startup).
class FunctionRegistry {
 public:
  // Registers a given RPC `handler` for a `service_name` and `method_name`.
  // `handler` is called for every incoming RPC to `service_name` and
  // `method_name`.
  // The return value is only provided for the convenience of initializing a
  // static variable, and is otherwise meaningless.
  bool RegisterRpcHandler(const std::string& service_name,
                          const std::string& method_name, RpcHandler handler);

  // Registers a given service `initializer`.
  // `initializer` is called once during server startup.
  // The return value is only provided for the convenience of initializing a
  // static variable, and is otherwise meaningless.
  bool RegisterRpcServiceInitializer(RpcServiceInitializer initializer);

  // Returns all registered service initializers.
  const std::vector<RpcServiceInitializer>& GetRpcServiceInitializers();

  // Looks up whether a RPC handler is registered under `service_name` and
  // `method_name`. If so, assigns `out` to it and returns true. Otherwise,
  // returns false.
  bool GetRpcHandler(const std::string& service_name,
                     const std::string& method_name, RpcHandler* out);

 private:
  std::unordered_map<std::string, ServiceRegistry> service_map_;
  std::vector<RpcServiceInitializer> service_initializers_;
};

// Provides access to the global instance of FunctionRegistry.
FunctionRegistry* GetGlobalFunctionRegistry();

}  // namespace wasm
}  // namespace sealed

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_FUNCTION_REGISTRY_H_
