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

#include "third_party/sealedcomputing/wasm3/enforcer/uefi_snp_guest/secrets_page.h"

#include "third_party/sealedcomputing/wasm3/enforcer/uefi_snp_guest/ConfidentialComputingSevSnpBlob.h"

STATIC EFI_GUID gConfidentialComputingSevSnpBlobGuid =
    CONFIDENTIAL_COMPUTING_SNP_BLOB_GUID;

SnpSecretsPage* GetSnpSecretsPage() {
  EFI_CONFIGURATION_TABLE* ect = gST->ConfigurationTable;
  for (UINTN i = 0; i < gST->NumberOfTableEntries; i++) {
    if (!CompareGuid(&gConfidentialComputingSevSnpBlobGuid,
                     &(ect->VendorGuid))) {
      CONFIDENTIAL_COMPUTING_SNP_BLOB_LOCATION* loc = ect->VendorTable;
      SnpSecretsPage* secrets_page =
          (SnpSecretsPage*)loc->SecretsPhysicalAddress;
      Print(L"SNP secrets page version: %08x \n", secrets_page->version);
      return secrets_page;
    }
    ect++;
  }
  return NULL;
}
