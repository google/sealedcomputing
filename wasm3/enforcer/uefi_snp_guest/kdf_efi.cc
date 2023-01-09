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

#include "third_party/sealedcomputing/wasm3/enforcer/uefi_snp_guest/kdf.h"

#include <stdio.h>
#include <string.h>

#include "third_party/sealedcomputing/wasm3/enforcer/uefi_crypto/aes.h"
#include "third_party/sealedcomputing/wasm3/enforcer/uefi_snp_guest/secrets_page.h"
#include "third_party/uefi_memory_encrypt/uefi_memory_encrypt.h"

namespace sealed {
namespace wasm {
namespace enforcer {

namespace {

// Definitions of SnpGuestMsg and types it depends on.
enum aead_algo {
  SNP_AEAD_INVALID,
  SNP_AEAD_AES_256_GCM,
};

#define MAX_AUTHTAG_LEN 32

#pragma pack(1)
// Table 97 at http://amd.com/system/files/TechDocs/56860.pdf
typedef struct {
  // Every field member is commented with offset for that field in dec.
  UINT8 authtag[MAX_AUTHTAG_LEN];  // 0
  UINT64 msg_seqno;                // 32
  UINT8 rsvd1[8];                  // 40
  UINT8 algo;                      // 48
  UINT8 hdr_version;               // 49
  UINT16 hdr_sz;                   // 50
  UINT8 msg_type;                  // 52
  UINT8 msg_version;               // 53
  UINT16 msg_sz;                   // 54
  UINT32 rsvd2;                    // 56
  UINT8 msg_vmpck;                 // 60
  UINT8 rsvd3[35];
} SnpGuestMsgHdr;

// Table 97 at http://amd.com/system/files/TechDocs/56860.pdf
typedef struct {
  SnpGuestMsgHdr hdr;
  UINT8 payload[4000];
} SnpGuestMsg;
#pragma pack()

// Bundle of context used by functions here.
typedef struct {
  SnpGuestMsg* request;
  SnpGuestMsg* response;
  SnpSecretsPage* secrets_page;
} KdfCtx;

// Global instance of KdfCtx.
KdfCtx* global_kdf_ctx = nullptr;

KdfCtx* KdfInit() {
  if (global_kdf_ctx != nullptr) {
    return global_kdf_ctx;
  }
  global_kdf_ctx = new KdfCtx();
  global_kdf_ctx->request =
      reinterpret_cast<SnpGuestMsg*>(UefiAllocateUnencryptedPages(1));
  global_kdf_ctx->response =
      reinterpret_cast<SnpGuestMsg*>(UefiAllocateUnencryptedPages(1));
  global_kdf_ctx->secrets_page = GetSnpSecretsPage();
  return global_kdf_ctx;
}

// Constants used in VerifyAndDecryptResponse.
#define AAD_LENGTH 48
#define IV_LENGTH 12

Status VerifyAndDecryptResponse(KdfCtx* ctx, SnpGuestMsg* req,
                                SnpGuestMsg* resp, uint8_t* payload,
                                uint32_t payload_size) {
  SnpGuestMsgHdr* req_hdr = &req->hdr;
  SnpGuestMsgHdr* resp_hdr = &resp->hdr;

  fprintf(stderr, "DEBUG: response [seqno %lu type %d version %d sz %d]\n",
          resp_hdr->msg_seqno, resp_hdr->msg_type, resp_hdr->msg_version,
          resp_hdr->msg_sz);

  // Verify that the sequence counter is incremented by 1.
  if (resp_hdr->msg_seqno != (req_hdr->msg_seqno + 1)) {
    return Status(kInternal,
                  "Error in SEV-SNP KDF: resp seqno does not match req seqno");
  }
  // Verify response message type and version number.
  if (resp_hdr->msg_type != (req_hdr->msg_type + 1) ||
      resp_hdr->msg_version != req_hdr->msg_version) {
    return Status(
        kInternal,
        "Error in SEV-SNP KDF: unexpected resp msg_type or msg_version");
  }
  // Verify response size matches expectation.
  if (resp_hdr->msg_sz > payload_size) {
    return Status(kInternal, "Error in SEV-SNP KDF: unexpected resp msg_sz");
  }

  // Decrypt response.
  auto key = SecretByteString(ctx->secrets_page->vmpck0,
                              uefi_crypto::kAes256KeyLength);
  ByteString iv(IV_LENGTH, 0);
  memcpy(iv.data(), &resp_hdr->msg_seqno, sizeof(resp_hdr->msg_seqno));
  ByteString ciphertext(resp_hdr->msg_sz + uefi_crypto::kAesGcmTagLength, 0);
  memcpy(ciphertext.data(), resp->payload, resp_hdr->msg_sz);
  memcpy(ciphertext.data() + resp_hdr->msg_sz, resp_hdr->authtag,
         uefi_crypto::kAesGcmTagLength);
  auto aad = ByteString(&resp_hdr->algo, AAD_LENGTH);
  SC_ASSIGN_OR_RETURN(
      SecretByteString plaintext,
      uefi_crypto::AesGcmDecrypt(key, iv, ciphertext, aad));
  if (plaintext.size() > payload_size) {
    return Status(kInternal,
                  "Error in SEV-SNP KDF: expected decrypted resp size");
  }
  memcpy(payload, plaintext.data(), plaintext.size());
  return Status::OkStatus();
}

#pragma pack(1)
// Table 18 at http://amd.com/system/files/TechDocs/56860.pdf
typedef struct {
  UINT32 root_key_select;
  UINT32 rsvd;
  UINT64 guest_field_select;
  UINT32 vmpl;
  UINT32 guest_svn;
  UINT64 tcb_version;
} SnpDerivedKeyReq;
// Table 19 at http://amd.com/system/files/TechDocs/56860.pdf
typedef struct {
  UINT32 status;
  UINT8 rsvd[28];
  UINT8 data[32];
} SnpDerivedKeyResp;
#pragma pack()

// From Table 99 at http://amd.com/system/files/TechDocs/56860.pdf
#define SNP_MSG_KEY_REQ 3
#define SNP_MSG_VERSION 1
#define MSG_HDR_VER 1

Status Kdf(SnpDerivedKeyReq* req, SnpDerivedKeyResp* resp) {
  KdfCtx* ctx = KdfInit();
  memset(resp, 0, sizeof(SnpDerivedKeyResp));
  memset(ctx->response, 0, sizeof(SnpGuestMsg));
  memset(ctx->request, 0, sizeof(SnpGuestMsg));

  // Prepare request header.
  SnpGuestMsgHdr* hdr = &ctx->request->hdr;
  hdr->algo = SNP_AEAD_AES_256_GCM;
  hdr->hdr_version = MSG_HDR_VER;
  hdr->hdr_sz = sizeof(*hdr);
  hdr->msg_type = SNP_MSG_KEY_REQ;
  hdr->msg_version = SNP_MSG_VERSION;
  hdr->msg_seqno = ctx->secrets_page->os_area.msg_seqno_0 + 1;
  hdr->msg_vmpck = 0;
  hdr->msg_sz = sizeof(*req);
  fprintf(stderr, "DEBUG: request [seqno %lu type %d version %d sz %d]\n",
          hdr->msg_seqno, hdr->msg_type, hdr->msg_version, hdr->msg_sz);

  // Encrypt derived key request.
  auto key = SecretByteString(ctx->secrets_page->vmpck0,
                              uefi_crypto::kAes256KeyLength);
  ByteString iv(IV_LENGTH, 0);
  memcpy(iv.data(), &hdr->msg_seqno, sizeof(hdr->msg_seqno));
  auto plaintext = SecretByteString(req, hdr->msg_sz);
  auto aad = ByteString(&hdr->algo, AAD_LENGTH);
  SC_ASSIGN_OR_RETURN(ByteString ciphertext,
                      uefi_crypto::AesGcmEncrypt(key, iv, plaintext, aad));
  memcpy(&ctx->request->payload, ciphertext.data(), hdr->msg_sz);
  memcpy(hdr->authtag, ciphertext.data() + hdr->msg_sz,
         uefi_crypto::kAesGcmTagLength);

  // Increment seqno.
  // If this function returns with an OK status, then this seqno is usable for
  // the next interaction with the PSP.
  // Otherwise, this seqno is likely out of sync with the PSP. However,
  // incrementing this seqno ensures it is not reused as an IV for AES GCM
  // encryption.
  ctx->secrets_page->os_area.msg_seqno_0 += 2;

  // Try, up to three times, calling VmgExit, verifying and decrypting the
  // response.
  // An error in any step leads to retrying. After retrying thrice, an error
  // status is returned.
  Status status;
  for (int i = 0; i < 3; ++i) {
    uint64_t exit_res =
        GuestMessageVmgExit(reinterpret_cast<uint64_t>(ctx->request),
                            reinterpret_cast<uint64_t>(ctx->response));
    if (exit_res != 0) {
      fprintf(stderr, "ERROR: non-zero result from VmgExit: %lu\n", exit_res);
      status = Status(kInternal, "Error in SEV-SNP KDF: VmgExit call failed");
      continue;
    }
    status = VerifyAndDecryptResponse(ctx, ctx->request, ctx->response,
                                              reinterpret_cast<uint8_t*>(resp),
                                              sizeof(SnpDerivedKeyResp));
    if (status.ok()) break;
  }
  return status;
}
}  // namespace

// Table 18 at https://amd.com/system/files/TechDocs/56860.pdf
// This is used in a bitmask field to request to the PSP that it mix in the
// initial launch digest measurement in the derived key.
#define GUEST_FIELD_SELECT_MEASUREMENT 1 << 3
#define GUEST_FIELD_SELECT_GUEST_POLCY 1
#define GUEST_FIELD_SELECT_MASK \
  GUEST_FIELD_SELECT_GUEST_POLCY | GUEST_FIELD_SELECT_MEASUREMENT

StatusOr<SecretByteString> GetSevSnpSealingKey() {
  SnpDerivedKeyReq req;
  SnpDerivedKeyResp resp;
  memset(&req, 0, sizeof(SnpDerivedKeyReq));

  req.guest_field_select |= (GUEST_FIELD_SELECT_MASK);

  SC_RETURN_IF_ERROR(Kdf(&req, &resp));

  if (resp.status != 0) {
    fprintf(stderr, "ERROR: non-OK status in SnpDerivedKeyResp: %u\n",
            resp.status);
    return Status(kInternal,
                  "SEV-SNP KDF failed, error in derive key response");
  }
  SecretByteString out(32, '\0');
  memcpy(out.data(), &resp.data, out.size());
  return out;
}

}  // namespace enforcer
}  // namespace wasm
}  // namespace sealed
