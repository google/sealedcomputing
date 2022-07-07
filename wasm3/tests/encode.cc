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

#include <string>

#include "third_party/sealedcomputing/rpc/encode_decode_lite.h"
#include "third_party/sealedcomputing/wasm3/base.h"
#include "third_party/sealedcomputing/wasm3/builtin/builtin_wasm.h"

extern "C" int start() {
  biPrintln("encode.cc: start function called");
  return 0;
}

extern "C" int WASM_EXPORT Encode_RPC(int32_t a, int32_t b) {
  sealed::rpc::Encoder encoder;
  encoder.String("a string");
  std::string encoded_string = encoder.Finish();
  biPrintln(encoded_string.c_str());
  biPrintln("encode.cc: Encode_RPC called");
  return 0;
}
