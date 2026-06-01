/**
 * tpm2-tss ESAPI wrapper — Full Implementation
 *
 * Build requires: libtss2-esys, libtss2-tctildr, libtss2-mu
 */

#include "tpm_esapi.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_mu.h>

/* ------------------------------------------------------------------ */
/*  NV index for the RSA EK certificate (TCG spec)                    */
/* ------------------------------------------------------------------ */
#define EK_CERT_NV_INDEX  0x01C00002

/* ------------------------------------------------------------------ */
/*  Internal context                                                   */
/* ------------------------------------------------------------------ */
struct TpmContext {
    ESYS_CONTEXT *esys_ctx;
    ESYS_TR       ek_handle;
    ESYS_TR       srk_handle;
    ESYS_TR       ak_handle;
};

/* ------------------------------------------------------------------ */
/*  Helpers: standard TPM2B_PUBLIC templates from the TCG EK          */
/*  Credential Profile and TCG AK naming spec                         */
/* ------------------------------------------------------------------ */

/* EK (RSA 2048, restricted decrypt, fixedTPM | fixedParent) */
static const TPM2B_PUBLIC ek_rsa_template = {
    .size = 0, /* filled by TPM */
    .publicArea = {
        .type = TPM2_ALG_RSA,
        .nameAlg = TPM2_ALG_SHA256,
        .objectAttributes = (
            TPMA_OBJECT_FIXEDTPM |
            TPMA_OBJECT_FIXEDPARENT |
            TPMA_OBJECT_SENSITIVEDATAORIGIN |
            TPMA_OBJECT_ADMINWITHPOLICY |
            TPMA_OBJECT_RESTRICTED |
            TPMA_OBJECT_DECRYPT
        ),
        .authPolicy = {
            .size = 32,
            /* TPM2_PolicySecret(TPM_RH_ENDORSEMENT) — standard EK policy */
            .buffer = {
                0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8,
                0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7, 0x24,
                0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
                0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA
            }
        },
        .parameters = {
            .rsaDetail = {
                .symmetric = {
                    .algorithm = TPM2_ALG_AES,
                    .keyBits = { .aes = 128 },
                    .mode    = { .aes = TPM2_ALG_CFB }
                },
                .scheme   = { .scheme = TPM2_ALG_NULL },
                .keyBits  = 2048,
                .exponent = 0   /* default 65537 */
            }
        },
        .unique = {
            .rsa = { .size = 256 }  /* zero-filled — tells TPM to generate */
        }
    }
};

/* SRK (RSA 2048, restricted decrypt under OWNER hierarchy) */
static const TPM2B_PUBLIC srk_rsa_template = {
    .size = 0,
    .publicArea = {
        .type = TPM2_ALG_RSA,
        .nameAlg = TPM2_ALG_SHA256,
        .objectAttributes = (
            TPMA_OBJECT_FIXEDTPM |
            TPMA_OBJECT_FIXEDPARENT |
            TPMA_OBJECT_SENSITIVEDATAORIGIN |
            TPMA_OBJECT_USERWITHAUTH |
            TPMA_OBJECT_RESTRICTED |
            TPMA_OBJECT_DECRYPT |
            TPMA_OBJECT_NODA
        ),
        .authPolicy = { .size = 0 },
        .parameters = {
            .rsaDetail = {
                .symmetric = {
                    .algorithm = TPM2_ALG_AES,
                    .keyBits = { .aes = 128 },
                    .mode    = { .aes = TPM2_ALG_CFB }
                },
                .scheme   = { .scheme = TPM2_ALG_NULL },
                .keyBits  = 2048,
                .exponent = 0
            }
        },
        .unique = {
            .rsa = { .size = 256 }
        }
    }
};

/* AK (RSA 2048, restricted signing, RSASSA-SHA256) */
static const TPM2B_PUBLIC ak_rsa_template = {
    .size = 0,
    .publicArea = {
        .type = TPM2_ALG_RSA,
        .nameAlg = TPM2_ALG_SHA256,
        .objectAttributes = (
            TPMA_OBJECT_FIXEDTPM |
            TPMA_OBJECT_FIXEDPARENT |
            TPMA_OBJECT_SENSITIVEDATAORIGIN |
            TPMA_OBJECT_USERWITHAUTH |
            TPMA_OBJECT_RESTRICTED |
            TPMA_OBJECT_SIGN_ENCRYPT
        ),
        .authPolicy = { .size = 0 },
        .parameters = {
            .rsaDetail = {
                .symmetric = {
                    .algorithm = TPM2_ALG_NULL
                },
                .scheme = {
                    .scheme = TPM2_ALG_RSASSA,
                    .details = { .rsassa = { .hashAlg = TPM2_ALG_SHA256 } }
                },
                .keyBits  = 2048,
                .exponent = 0
            }
        },
        .unique = {
            .rsa = { .size = 256 }
        }
    }
};

/* Empty sensitive create for CreatePrimary / Create */
static const TPM2B_SENSITIVE_CREATE empty_sensitive = {
    .size = 0,
    .sensitive = {
        .userAuth = { .size = 0 },
        .data     = { .size = 0 }
    }
};

static const TPM2B_DATA empty_outside_info = { .size = 0 };
static const TPML_PCR_SELECTION empty_creation_pcr = { .count = 0 };

/* ------------------------------------------------------------------ */
/*  Lifecycle                                                          */
/* ------------------------------------------------------------------ */

TpmContext* tpm_open(void)
{
    TpmContext* ctx = calloc(1, sizeof(TpmContext));
    if (!ctx) return NULL;

    ctx->ek_handle  = ESYS_TR_NONE;
    ctx->srk_handle = ESYS_TR_NONE;
    ctx->ak_handle  = ESYS_TR_NONE;

    /* Auto-detect TCTI (tpm2-abrmd or /dev/tpmrm0) */
    TSS2_RC rc = Esys_Initialize(&ctx->esys_ctx, NULL, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        RH_LOG_WARN("tpm_open: Esys_Initialize failed: 0x%x\n", (unsigned)rc);
        free(ctx);
        return NULL;
    }

    return ctx;
}

void tpm_close(TpmContext* ctx)
{
    if (!ctx) return;

    if (ctx->ak_handle != ESYS_TR_NONE)
        Esys_FlushContext(ctx->esys_ctx, ctx->ak_handle);

    if (ctx->srk_handle != ESYS_TR_NONE)
        Esys_FlushContext(ctx->esys_ctx, ctx->srk_handle);

    if (ctx->ek_handle != ESYS_TR_NONE)
        Esys_FlushContext(ctx->esys_ctx, ctx->ek_handle);

    if (ctx->esys_ctx)
        Esys_Finalize(&ctx->esys_ctx);

    free(ctx);
}

int tpm_is_available(void)
{
    int fd = open("/dev/tpmrm0", O_RDWR);
    if (fd >= 0) {
        close(fd);
        return 1;
    }
    /* Fall back to check /dev/tpm0 */
    fd = open("/dev/tpm0", O_RDWR);
    if (fd >= 0) {
        close(fd);
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  EK certificate from NV (0x01C00002)                               */
/* ------------------------------------------------------------------ */

int tpm_read_ek_cert(TpmContext* ctx, uint8_t* out_cert, size_t* out_cert_len)
{
    if (!ctx || !ctx->esys_ctx || !out_cert_len)
        return -1;

    TSS2_RC rc;
    ESYS_TR nv_index_handle = ESYS_TR_NONE;
    TPM2B_NV_PUBLIC *nv_public = NULL;
    TPM2B_NAME *nv_name = NULL;
    TPM2B_MAX_NV_BUFFER *nv_data = NULL;

    /* Convert the NV index to an ESYS_TR */
    rc = Esys_TR_FromTPMPublic(ctx->esys_ctx, EK_CERT_NV_INDEX,
                               ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               &nv_index_handle);
    if (rc != TSS2_RC_SUCCESS) {
        RH_LOG_WARN("tpm_read_ek_cert: TR_FromTPMPublic failed: 0x%x\n", (unsigned)rc);
        return -1;
    }

    /* Read NV public to get the size */
    rc = Esys_NV_ReadPublic(ctx->esys_ctx, nv_index_handle,
                            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                            &nv_public, &nv_name);
    if (rc != TSS2_RC_SUCCESS) {
        RH_LOG_WARN("tpm_read_ek_cert: NV_ReadPublic failed: 0x%x\n", (unsigned)rc);
        return -1;
    }

    uint16_t nv_size = nv_public->nvPublic.dataSize;
    Esys_Free(nv_name);
    Esys_Free(nv_public);

    if (!out_cert) {
        /* Caller wants to know the size */
        *out_cert_len = nv_size;
        return 0;
    }

    if (*out_cert_len < nv_size) {
        *out_cert_len = nv_size;
        return -1;
    }

    /* Read the NV data — may need to read in chunks of MAX_NV_BUFFER_SIZE */
    size_t offset = 0;
    while (offset < nv_size) {
        uint16_t chunk = nv_size - (uint16_t)offset;
        if (chunk > TPM2_MAX_NV_BUFFER_SIZE)
            chunk = TPM2_MAX_NV_BUFFER_SIZE;

        rc = Esys_NV_Read(ctx->esys_ctx, nv_index_handle, nv_index_handle,
                          ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                          chunk, (uint16_t)offset, &nv_data);
        if (rc != TSS2_RC_SUCCESS) {
            RH_LOG_WARN("tpm_read_ek_cert: NV_Read failed at offset %zu: 0x%x\n",
                    offset, (unsigned)rc);
            return -1;
        }

        memcpy(out_cert + offset, nv_data->buffer, nv_data->size);
        offset += nv_data->size;
        Esys_Free(nv_data);
        nv_data = NULL;
    }

    *out_cert_len = nv_size;
    return 0;
}

/* ------------------------------------------------------------------ */
/*  EK public key (create primary under ENDORSEMENT)                  */
/* ------------------------------------------------------------------ */

int tpm_read_ek_pub(TpmContext* ctx, uint8_t* out_pub, size_t* out_pub_len)
{
    if (!ctx || !ctx->esys_ctx || !out_pub_len)
        return -1;

    TSS2_RC rc;
    TPM2B_PUBLIC *out_public = NULL;
    TPM2B_CREATION_DATA *creation_data = NULL;
    TPM2B_DIGEST *creation_hash = NULL;
    TPMT_TK_CREATION *creation_ticket = NULL;

    /* If EK is already loaded, flush it first */
    if (ctx->ek_handle != ESYS_TR_NONE) {
        Esys_FlushContext(ctx->esys_ctx, ctx->ek_handle);
        ctx->ek_handle = ESYS_TR_NONE;
    }

    rc = Esys_CreatePrimary(
        ctx->esys_ctx,
        ESYS_TR_RH_ENDORSEMENT,   /* hierarchy */
        ESYS_TR_PASSWORD,          /* session for auth */
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &empty_sensitive,
        &ek_rsa_template,
        &empty_outside_info,
        &empty_creation_pcr,
        &ctx->ek_handle,
        &out_public,
        &creation_data,
        &creation_hash,
        &creation_ticket
    );

    Esys_Free(creation_data);
    Esys_Free(creation_hash);
    Esys_Free(creation_ticket);

    if (rc != TSS2_RC_SUCCESS) {
        RH_LOG_WARN("tpm_read_ek_pub: CreatePrimary failed: 0x%x\n", (unsigned)rc);
        return -1;
    }

    /* Marshal TPM2B_PUBLIC to bytes */
    uint8_t marshal_buf[sizeof(TPM2B_PUBLIC) + 8];
    size_t marshal_offset = 0;
    rc = Tss2_MU_TPM2B_PUBLIC_Marshal(out_public, marshal_buf,
                                       sizeof(marshal_buf), &marshal_offset);
    Esys_Free(out_public);

    if (rc != TSS2_RC_SUCCESS) {
        RH_LOG_WARN("tpm_read_ek_pub: Marshal failed: 0x%x\n", (unsigned)rc);
        return -1;
    }

    if (!out_pub) {
        *out_pub_len = marshal_offset;
        return 0;
    }

    if (*out_pub_len < marshal_offset) {
        *out_pub_len = marshal_offset;
        return -1;
    }

    memcpy(out_pub, marshal_buf, marshal_offset);
    *out_pub_len = marshal_offset;
    return 0;
}

/* ------------------------------------------------------------------ */
/*  AK creation (SRK + AK under OWNER hierarchy)                     */
/* ------------------------------------------------------------------ */

int tpm_create_ak(TpmContext* ctx)
{
    if (!ctx || !ctx->esys_ctx)
        return -1;

    TSS2_RC rc;
    TPM2B_PUBLIC *srk_public = NULL;
    TPM2B_CREATION_DATA *creation_data = NULL;
    TPM2B_DIGEST *creation_hash = NULL;
    TPMT_TK_CREATION *creation_ticket = NULL;

    /* 1. Create SRK under OWNER hierarchy */
    if (ctx->srk_handle != ESYS_TR_NONE) {
        Esys_FlushContext(ctx->esys_ctx, ctx->srk_handle);
        ctx->srk_handle = ESYS_TR_NONE;
    }

    rc = Esys_CreatePrimary(
        ctx->esys_ctx,
        ESYS_TR_RH_OWNER,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &empty_sensitive,
        &srk_rsa_template,
        &empty_outside_info,
        &empty_creation_pcr,
        &ctx->srk_handle,
        &srk_public,
        &creation_data,
        &creation_hash,
        &creation_ticket
    );

    Esys_Free(srk_public);
    Esys_Free(creation_data);
    Esys_Free(creation_hash);
    Esys_Free(creation_ticket);

    if (rc != TSS2_RC_SUCCESS) {
        RH_LOG_WARN("tpm_create_ak: CreatePrimary(SRK) failed: 0x%x\n", (unsigned)rc);
        return -1;
    }

    /* 2. Create AK as child of SRK (restricted signing, RSASSA-SHA256) */
    TPM2B_PRIVATE *ak_private = NULL;
    TPM2B_PUBLIC *ak_public = NULL;

    rc = Esys_Create(
        ctx->esys_ctx,
        ctx->srk_handle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &empty_sensitive,
        &ak_rsa_template,
        &empty_outside_info,
        &empty_creation_pcr,
        &ak_private,
        &ak_public,
        &creation_data,
        &creation_hash,
        &creation_ticket
    );

    Esys_Free(creation_data);
    Esys_Free(creation_hash);
    Esys_Free(creation_ticket);

    if (rc != TSS2_RC_SUCCESS) {
        RH_LOG_WARN("tpm_create_ak: Create(AK) failed: 0x%x\n", (unsigned)rc);
        Esys_Free(ak_private);
        Esys_Free(ak_public);
        return -1;
    }

    /* 3. Load AK into TPM */
    if (ctx->ak_handle != ESYS_TR_NONE) {
        Esys_FlushContext(ctx->esys_ctx, ctx->ak_handle);
        ctx->ak_handle = ESYS_TR_NONE;
    }

    rc = Esys_Load(
        ctx->esys_ctx,
        ctx->srk_handle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ak_private,
        ak_public,
        &ctx->ak_handle
    );

    Esys_Free(ak_private);
    Esys_Free(ak_public);

    if (rc != TSS2_RC_SUCCESS) {
        RH_LOG_WARN("tpm_create_ak: Load(AK) failed: 0x%x\n", (unsigned)rc);
        return -1;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Get AK public area (marshalled TPM2B_PUBLIC)                      */
/* ------------------------------------------------------------------ */

int tpm_get_ak_pub(TpmContext* ctx, uint8_t* out_pub, size_t* out_pub_len)
{
    if (!ctx || !ctx->esys_ctx || !out_pub_len)
        return -1;

    if (ctx->ak_handle == ESYS_TR_NONE)
        return -1;

    TSS2_RC rc;
    TPM2B_PUBLIC *pub = NULL;
    TPM2B_NAME *name = NULL;
    TPM2B_NAME *qualified_name = NULL;

    rc = Esys_ReadPublic(
        ctx->esys_ctx,
        ctx->ak_handle,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &pub,
        &name,
        &qualified_name
    );

    Esys_Free(name);
    Esys_Free(qualified_name);

    if (rc != TSS2_RC_SUCCESS) {
        RH_LOG_WARN("tpm_get_ak_pub: ReadPublic failed: 0x%x\n", (unsigned)rc);
        return -1;
    }

    /* Marshal */
    uint8_t marshal_buf[sizeof(TPM2B_PUBLIC) + 8];
    size_t marshal_offset = 0;
    rc = Tss2_MU_TPM2B_PUBLIC_Marshal(pub, marshal_buf,
                                       sizeof(marshal_buf), &marshal_offset);
    Esys_Free(pub);

    if (rc != TSS2_RC_SUCCESS)
        return -1;

    if (!out_pub) {
        *out_pub_len = marshal_offset;
        return 0;
    }

    if (*out_pub_len < marshal_offset) {
        *out_pub_len = marshal_offset;
        return -1;
    }

    memcpy(out_pub, marshal_buf, marshal_offset);
    *out_pub_len = marshal_offset;
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Get AK name (TPM2B_NAME)                                          */
/* ------------------------------------------------------------------ */

int tpm_get_ak_name(TpmContext* ctx, uint8_t* out_name, size_t* out_name_len)
{
    if (!ctx || !ctx->esys_ctx || !out_name_len)
        return -1;

    if (ctx->ak_handle == ESYS_TR_NONE)
        return -1;

    TSS2_RC rc;
    TPM2B_PUBLIC *pub = NULL;
    TPM2B_NAME *name = NULL;
    TPM2B_NAME *qualified_name = NULL;

    rc = Esys_ReadPublic(
        ctx->esys_ctx,
        ctx->ak_handle,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &pub,
        &name,
        &qualified_name
    );

    Esys_Free(pub);
    Esys_Free(qualified_name);

    if (rc != TSS2_RC_SUCCESS) {
        RH_LOG_WARN("tpm_get_ak_name: ReadPublic failed: 0x%x\n", (unsigned)rc);
        return -1;
    }

    if (!out_name) {
        *out_name_len = name->size;
        Esys_Free(name);
        return 0;
    }

    if (*out_name_len < name->size) {
        *out_name_len = name->size;
        Esys_Free(name);
        return -1;
    }

    memcpy(out_name, name->name, name->size);
    *out_name_len = name->size;
    Esys_Free(name);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  TPM Quote                                                          */
/* ------------------------------------------------------------------ */

int tpm_quote(TpmContext* ctx,
              const uint8_t* nonce, size_t nonce_len,
              const uint32_t* pcr_indices, size_t pcr_count,
              uint8_t* out_quoted, size_t* out_quoted_len,
              uint8_t* out_sig, size_t* out_sig_len)
{
    if (!ctx || !ctx->esys_ctx || !nonce || !pcr_indices ||
        !out_quoted_len || !out_sig_len)
        return -1;

    if (ctx->ak_handle == ESYS_TR_NONE)
        return -1;

    /* Build qualifying data (nonce) */
    TPM2B_DATA qualifying_data = { .size = 0 };
    if (nonce_len > sizeof(qualifying_data.buffer))
        nonce_len = sizeof(qualifying_data.buffer);
    qualifying_data.size = (uint16_t)nonce_len;
    memcpy(qualifying_data.buffer, nonce, nonce_len);

    /* Build PCR selection — SHA-256 bank */
    TPML_PCR_SELECTION pcr_selection = {
        .count = 1,
        .pcrSelections = {{
            .hash = TPM2_ALG_SHA256,
            .sizeofSelect = 3,
            .pcrSelect = { 0, 0, 0 }
        }}
    };
    for (size_t i = 0; i < pcr_count && i < 24; i++) {
        uint32_t idx = pcr_indices[i];
        if (idx < 24)
            pcr_selection.pcrSelections[0].pcrSelect[idx / 8] |= (1 << (idx % 8));
    }

    /* Use RSASSA as the signing scheme (matches AK template) */
    TPMT_SIG_SCHEME scheme = {
        .scheme = TPM2_ALG_NULL  /* use AK's default scheme */
    };

    TPM2B_ATTEST *quoted_info = NULL;
    TPMT_SIGNATURE *signature = NULL;

    TSS2_RC rc = Esys_Quote(
        ctx->esys_ctx,
        ctx->ak_handle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &qualifying_data,
        &scheme,
        &pcr_selection,
        &quoted_info,
        &signature
    );

    if (rc != TSS2_RC_SUCCESS) {
        RH_LOG_WARN("tpm_quote: Esys_Quote failed: 0x%x\n", (unsigned)rc);
        return -1;
    }

    /* Copy quoted info */
    if (out_quoted) {
        if (*out_quoted_len < quoted_info->size) {
            *out_quoted_len = quoted_info->size;
            Esys_Free(quoted_info);
            Esys_Free(signature);
            return -1;
        }
        memcpy(out_quoted, quoted_info->attestationData, quoted_info->size);
    }
    *out_quoted_len = quoted_info->size;

    /* Marshal signature */
    uint8_t sig_buf[sizeof(TPMT_SIGNATURE) + 8];
    size_t sig_offset = 0;
    rc = Tss2_MU_TPMT_SIGNATURE_Marshal(signature, sig_buf,
                                          sizeof(sig_buf), &sig_offset);
    if (rc != TSS2_RC_SUCCESS) {
        Esys_Free(quoted_info);
        Esys_Free(signature);
        return -1;
    }

    if (out_sig) {
        if (*out_sig_len < sig_offset) {
            *out_sig_len = sig_offset;
            Esys_Free(quoted_info);
            Esys_Free(signature);
            return -1;
        }
        memcpy(out_sig, sig_buf, sig_offset);
    }
    *out_sig_len = sig_offset;

    Esys_Free(quoted_info);
    Esys_Free(signature);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  PCR Read                                                           */
/* ------------------------------------------------------------------ */

int tpm_pcr_read(TpmContext* ctx,
                 uint32_t pcr_index,
                 uint8_t* out_digest, size_t* out_digest_len)
{
    if (!ctx || !ctx->esys_ctx || !out_digest_len)
        return -1;

    if (pcr_index > 23)
        return -1;

    TPML_PCR_SELECTION pcr_selection_in = {
        .count = 1,
        .pcrSelections = {{
            .hash = TPM2_ALG_SHA256,
            .sizeofSelect = 3,
            .pcrSelect = { 0, 0, 0 }
        }}
    };
    pcr_selection_in.pcrSelections[0].pcrSelect[pcr_index / 8] |= (1 << (pcr_index % 8));

    uint32_t pcr_update_counter = 0;
    TPML_PCR_SELECTION *pcr_selection_out = NULL;
    TPML_DIGEST *pcr_values = NULL;

    TSS2_RC rc = Esys_PCR_Read(
        ctx->esys_ctx,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &pcr_selection_in,
        &pcr_update_counter,
        &pcr_selection_out,
        &pcr_values
    );

    Esys_Free(pcr_selection_out);

    if (rc != TSS2_RC_SUCCESS) {
        RH_LOG_WARN("tpm_pcr_read: PCR_Read failed: 0x%x\n", (unsigned)rc);
        return -1;
    }

    if (pcr_values->count == 0) {
        Esys_Free(pcr_values);
        return -1;
    }

    uint16_t digest_size = pcr_values->digests[0].size;
    if (!out_digest) {
        *out_digest_len = digest_size;
        Esys_Free(pcr_values);
        return 0;
    }

    if (*out_digest_len < digest_size) {
        *out_digest_len = digest_size;
        Esys_Free(pcr_values);
        return -1;
    }

    memcpy(out_digest, pcr_values->digests[0].buffer, digest_size);
    *out_digest_len = digest_size;

    Esys_Free(pcr_values);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Credential Activation                                              */
/* ------------------------------------------------------------------ */

int tpm_activate_credential(TpmContext* ctx,
                            const uint8_t* cred_blob, size_t cred_blob_len,
                            const uint8_t* secret, size_t secret_len,
                            uint8_t* out_cert_info, size_t* out_cert_info_len)
{
    if (!ctx || !ctx->esys_ctx || !cred_blob || !secret || !out_cert_info_len)
        return -1;

    if (ctx->ak_handle == ESYS_TR_NONE || ctx->ek_handle == ESYS_TR_NONE)
        return -1;

    /* Build TPM2B_ID_OBJECT (credential blob) */
    TPM2B_ID_OBJECT credential_blob = { .size = 0 };
    if (cred_blob_len > sizeof(credential_blob.credential))
        return -1;
    credential_blob.size = (uint16_t)cred_blob_len;
    memcpy(credential_blob.credential, cred_blob, cred_blob_len);

    /* Build TPM2B_ENCRYPTED_SECRET */
    TPM2B_ENCRYPTED_SECRET encrypted_secret = { .size = 0 };
    if (secret_len > sizeof(encrypted_secret.secret))
        return -1;
    encrypted_secret.size = (uint16_t)secret_len;
    memcpy(encrypted_secret.secret, secret, secret_len);

    /*
     * ActivateCredential requires:
     *   - activateHandle = AK (object whose name is bound in the credential)
     *   - keyHandle = EK (the key used to protect the credential)
     *
     * The EK requires a policy session (PolicySecret with Endorsement auth).
     * We need to set up an HMAC session for the AK and a policy session
     * for the EK.
     */
    ESYS_TR policy_session = ESYS_TR_NONE;
    TSS2_RC rc;

    /* Start a policy session for the EK */
    TPMT_SYM_DEF sym_def = {
        .algorithm = TPM2_ALG_AES,
        .keyBits = { .aes = 128 },
        .mode = { .aes = TPM2_ALG_CFB }
    };

    rc = Esys_StartAuthSession(
        ctx->esys_ctx,
        ESYS_TR_NONE,       /* tpmKey — unbound */
        ESYS_TR_NONE,       /* bind — unbound */
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        NULL,               /* nonceCaller — auto-generated */
        TPM2_SE_POLICY,
        &sym_def,
        TPM2_ALG_SHA256,
        &policy_session
    );
    if (rc != TSS2_RC_SUCCESS) {
        RH_LOG_WARN("tpm_activate_credential: StartAuthSession failed: 0x%x\n", (unsigned)rc);
        return -1;
    }

    /* Execute PolicySecret(ENDORSEMENT) to satisfy the EK policy */
    TPM2B_TIMEOUT *timeout = NULL;
    TPMT_TK_AUTH *policy_ticket = NULL;

    TPM2B_NONCE nonce_tpm = { .size = 0 };
    TPM2B_DIGEST cp_hash_a = { .size = 0 };
    TPM2B_NONCE policy_ref = { .size = 0 };
    int32_t expiration = 0;

    rc = Esys_PolicySecret(
        ctx->esys_ctx,
        ESYS_TR_RH_ENDORSEMENT,
        policy_session,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &nonce_tpm,
        &cp_hash_a,
        &policy_ref,
        expiration,
        &timeout,
        &policy_ticket
    );

    Esys_Free(timeout);
    Esys_Free(policy_ticket);

    if (rc != TSS2_RC_SUCCESS) {
        RH_LOG_WARN("tpm_activate_credential: PolicySecret failed: 0x%x\n", (unsigned)rc);
        Esys_FlushContext(ctx->esys_ctx, policy_session);
        return -1;
    }

    /* Now call ActivateCredential:
     *   session1 = ESYS_TR_PASSWORD (for AK auth)
     *   session2 = policy_session   (for EK auth)
     */
    TPM2B_DIGEST *cert_info = NULL;

    rc = Esys_ActivateCredential(
        ctx->esys_ctx,
        ctx->ak_handle,
        ctx->ek_handle,
        ESYS_TR_PASSWORD,     /* AK auth */
        policy_session,       /* EK auth via policy */
        ESYS_TR_NONE,
        &credential_blob,
        &encrypted_secret,
        &cert_info
    );

    /* Policy session is consumed by ActivateCredential */

    if (rc != TSS2_RC_SUCCESS) {
        RH_LOG_WARN("tpm_activate_credential: ActivateCredential failed: 0x%x\n", (unsigned)rc);
        return -1;
    }

    if (!out_cert_info) {
        *out_cert_info_len = cert_info->size;
        Esys_Free(cert_info);
        return 0;
    }

    if (*out_cert_info_len < cert_info->size) {
        *out_cert_info_len = cert_info->size;
        Esys_Free(cert_info);
        return -1;
    }

    memcpy(out_cert_info, cert_info->buffer, cert_info->size);
    *out_cert_info_len = cert_info->size;
    Esys_Free(cert_info);
    return 0;
}
