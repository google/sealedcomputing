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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_EFI_UTILS_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_EFI_UTILS_H_

#ifdef __cplusplus
extern "C" {
#endif

// This function, if called in a UEFI application in a microVM, disables the
// watchdog timer that restarts the microVM every 5 minutes. See b/247896905 for
// more context. This function is a no-op in other contexts (i.e. when
// compilation target is Linux or WASM).
void disable_watchdog_timer();

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_EFI_UTILS_H_
