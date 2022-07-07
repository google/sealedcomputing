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

#include "third_party/sealedcomputing/wasm3/enforcer/function_registry.h"

namespace sealed {
namespace wasm {

namespace {

FunctionRegistry* global_registry = nullptr;

}

FunctionRegistry* GetGlobalFunctionRegistry() {
  if (global_registry == nullptr) {
    global_registry = new FunctionRegistry();
  }
  return global_registry;
}

bool FunctionRegistry::RegisterRpcHandler(const std::string& service_name,
                                          const std::string& method_name,
                                          RpcHandler handler) {
  auto it = service_map_.find(service_name);
  if (it == service_map_.end()) {
    service_map_[service_name] = ServiceRegistry(service_name);
    it = service_map_.find(service_name);
  }
  ServiceRegistry& service = it->second;
  service.RegisterRpc(method_name, handler);
  return true;
}

bool FunctionRegistry::GetRpcHandler(const std::string& service_name,
                                     const std::string& method_name,
                                     RpcHandler* out) {
  auto it = service_map_.find(service_name);
  if (it == service_map_.end()) {
    return false;
  }
  ServiceRegistry& service = it->second;
  RpcHandler handler = service.GetHandler(method_name);
  if (handler == nullptr) {
    return false;
  }
  *out = *handler;
  return true;
}

bool FunctionRegistry::RegisterRpcServiceInitializer(
    RpcServiceInitializer initializer) {
  service_initializers_.push_back(initializer);
  return true;
}

const std::vector<RpcServiceInitializer>&
FunctionRegistry::GetRpcServiceInitializers() {
  return service_initializers_;
}

}  // namespace wasm
}  // namespace sealed
