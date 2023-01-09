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

/** @file
   UEFI Configuration Table for exposing the SEV-SNP launch blob.

   Copyright (c) 2021, Advanced Micro Devices Inc. All right reserved.

   SPDX-License-Identifier: BSD-2-Clause-Patent
 **/

#ifndef CONFIDENTIAL_COMPUTING_SEV_SNP_BLOB_H_
#define CONFIDENTIAL_COMPUTING_SEV_SNP_BLOB_H_

#define CONFIDENTIAL_COMPUTING_SNP_BLOB_GUID              \
  {                                                       \
    0x067b1f5f, 0xcf26, 0x44c5,                           \
        {0x85, 0x54, 0x93, 0xd7, 0x77, 0x91, 0x2d, 0x42}, \
  }

typedef struct {
  UINT32 Header;
  UINT16 Version;
  UINT16 Reserved1;
  UINT64 SecretsPhysicalAddress;
  UINT32 SecretsSize;
  UINT64 CpuidPhysicalAddress;
  UINT32 CpuidLSize;
} CONFIDENTIAL_COMPUTING_SNP_BLOB_LOCATION;

extern EFI_GUID gConfidentialComputingSevSnpBlobGuid;

#endif
