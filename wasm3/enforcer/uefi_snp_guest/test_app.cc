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

#include <stdio.h>

#include "third_party/sealedcomputing/wasm3/efi_utils.h"
#include "third_party/sealedcomputing/wasm3/enforcer/uefi_snp_guest/kdf.h"
#include "third_party/sealedcomputing/wasm3/enforcer/uefi_snp_guest/secrets_page.h"
#include "third_party/uefi_memory_encrypt/uefi_memory_encrypt.h"

int uefi_shutdown() {
  int status;
  status = uefi_call_wrapper(RT->ResetSystem, 4, EfiResetShutdown, EFI_SUCCESS,
                             0, NULL);
  if (status != 0) {
    fprintf(stderr, "Shutdown failed.\n");
  }
  return status;
}

void PrintByteArray(uint8_t data[], size_t size) {
  char output[(size * 2) + 1];
  char* ptr = &output[0];
  for (size_t i = 0; i < size; ++i) {
    ptr += snprintf(ptr, sizeof(output), "%02X", data[i]);
  }
  printf("key: %s\n", output);
}

int main() {
  disable_watchdog_timer();

  if (IsSevSnpEnabled()) {
    printf("SEV-SNP is enabled\n");
  }

  printf("Hello World MicroVM testing.\n");
  SnpSecretsPage* page = GetSnpSecretsPage();
  if (page == NULL) {
    printf("Error locating secrets page\n");
  } else {
    printf("Secrets page GPA: %p\n", page);
  }

  auto key = sealed::wasm::enforcer::GetSevSnpSealingKey();
  if (!key.ok()) {
    printf("Error getting SEV-SNP sealing key\n");
  } else {
    PrintByteArray(key->data(), key->size());
  }

  return uefi_shutdown();
}
