/**
 * tpm2-tss ESAPI wrapper for TPM 2.0 attestation operations.
 */

#ifndef ROOTHERALD_TPM_ESAPI_H
#define ROOTHERALD_TPM_ESAPI_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct TpmContext TpmContext;

/* Lifecycle */
TpmContext* tpm_open(void);
void tpm_close(TpmContext* ctx);
int tpm_is_available(void);

/* EK operations */
int tpm_read_ek_cert(TpmContext* ctx, uint8_t* out_cert, size_t* out_cert_len);
int tpm_read_ek_pub(TpmContext* ctx, uint8_t* out_pub, size_t* out_pub_len);

/* AK operations */
int tpm_create_ak(TpmContext* ctx);
int tpm_get_ak_pub(TpmContext* ctx, uint8_t* out_pub, size_t* out_pub_len);
int tpm_get_ak_name(TpmContext* ctx, uint8_t* out_name, size_t* out_name_len);

/* Quote */
int tpm_quote(TpmContext* ctx,
              const uint8_t* nonce, size_t nonce_len,
              const uint32_t* pcr_indices, size_t pcr_count,
              uint8_t* out_quoted, size_t* out_quoted_len,
              uint8_t* out_sig, size_t* out_sig_len);

/* PCR Read */
int tpm_pcr_read(TpmContext* ctx,
                 uint32_t pcr_index,
                 uint8_t* out_digest, size_t* out_digest_len);

/* Credential activation */
int tpm_activate_credential(TpmContext* ctx,
                            const uint8_t* cred_blob, size_t cred_blob_len,
                            const uint8_t* secret, size_t secret_len,
                            uint8_t* out_cert_info, size_t* out_cert_info_len);

#ifdef __cplusplus
}
#endif

#endif /* ROOTHERALD_TPM_ESAPI_H */
