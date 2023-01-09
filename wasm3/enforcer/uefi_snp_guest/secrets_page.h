//  Copyright 2021 Google LLC.
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

#ifndef THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_UEFI_SNP_GUEST_SECRETS_PAGE_H_
#define THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_UEFI_SNP_GUEST_SECRETS_PAGE_H_

#include <efi.h>
#include <efilib.h>

#ifdef __cplusplus
extern "C" {
#endif

// The secrets page contains 96-bytes of reserved field that can be used by
// the guest OS. The guest OS uses the area to save the message sequence
// number for each VMPCK.
// See the GHCB spec section Secret page layout for the format for this area.
#pragma pack(1)
typedef struct {
  UINT32 msg_seqno_0;
  UINT32 msg_seqno_1;
  UINT32 msg_seqno_2;
  UINT32 msg_seqno_3;
  UINT64 ap_jump_table_pa;
  UINT8 rsvd[40];
  UINT8 guest_usage[32];
} SecretsOsArea;

#define VMPCK_KEY_LEN 32

// See the SNP ABI spec for secrets page format.
// Table 68 at https://www.amd.com/system/files/TechDocs/56860.pdf
typedef struct {
  UINT32 version;
  UINT32 imien : 1, rsvd1 : 31;
  UINT32 fms;
  UINT32 rsvd2;
  UINT8 gosvw[16];
  UINT8 vmpck0[VMPCK_KEY_LEN];
  UINT8 vmpck1[VMPCK_KEY_LEN];
  UINT8 vmpck2[VMPCK_KEY_LEN];
  UINT8 vmpck3[VMPCK_KEY_LEN];
  SecretsOsArea os_area;
  UINT8 rsvd3[3840];
} SnpSecretsPage;
#pragma pack()

// Returns the address to the secrets page.
// Returns NULL if secrets page was not located.
SnpSecretsPage* GetSnpSecretsPage();

#ifdef __cplusplus
}
#endif

#endif  // THIRD_PARTY_SEALEDCOMPUTING_WASM3_ENFORCER_UEFI_SNP_GUEST_SECRETS_PAGE_H_
