/**
 *  Root Herald Linux Client SDK — Full Implementation
 *
 * Uses tpm2-tss ESAPI for TPM 2.0 access.
 * Uses libcurl for server communication.
 */

#include "rootherald_linux.h"
#include "tpm_esapi.h"
#include "event_log.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/*  External: http_curl.c                                              */
/* ------------------------------------------------------------------ */
extern int http_post_json(const char* url, const char* json_body,
                          char* response_buf, size_t response_buf_len);
extern int http_get(const char* url,
                    char* response_buf, size_t response_buf_len);

/* ------------------------------------------------------------------ */
/*  Base64 encode / decode (inline, no external dependency)           */
/* ------------------------------------------------------------------ */

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t base64_encode(const uint8_t* src, size_t src_len,
                            char* dst, size_t dst_len)
{
    size_t needed = 4 * ((src_len + 2) / 3) + 1;
    if (!dst || dst_len < needed)
        return needed;

    size_t di = 0;
    for (size_t i = 0; i < src_len; i += 3) {
        uint32_t a = src[i];
        uint32_t b = (i + 1 < src_len) ? src[i + 1] : 0;
        uint32_t c = (i + 2 < src_len) ? src[i + 2] : 0;
        uint32_t triple = (a << 16) | (b << 8) | c;

        dst[di++] = b64_table[(triple >> 18) & 0x3F];
        dst[di++] = b64_table[(triple >> 12) & 0x3F];
        dst[di++] = (i + 1 < src_len) ? b64_table[(triple >> 6) & 0x3F] : '=';
        dst[di++] = (i + 2 < src_len) ? b64_table[triple & 0x3F] : '=';
    }
    dst[di] = '\0';
    return di;
}

static int b64_decode_char(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static size_t base64_decode(const char* src, size_t src_len,
                            uint8_t* dst, size_t dst_len)
{
    if (!src || src_len == 0) return 0;

    /* Strip trailing padding for length calculation */
    size_t padding = 0;
    if (src_len > 0 && src[src_len - 1] == '=') padding++;
    if (src_len > 1 && src[src_len - 2] == '=') padding++;

    size_t out_len = (src_len / 4) * 3 - padding;
    if (!dst || dst_len < out_len)
        return out_len;

    size_t di = 0;
    for (size_t i = 0; i < src_len; i += 4) {
        int a = b64_decode_char(src[i]);
        int b = (i + 1 < src_len) ? b64_decode_char(src[i + 1]) : 0;
        int c = (i + 2 < src_len) ? b64_decode_char(src[i + 2]) : 0;
        int d = (i + 3 < src_len) ? b64_decode_char(src[i + 3]) : 0;

        if (a < 0) a = 0;
        if (b < 0) b = 0;
        if (c < 0) c = 0;
        if (d < 0) d = 0;

        uint32_t triple = ((uint32_t)a << 18) | ((uint32_t)b << 12) |
                          ((uint32_t)c << 6) | (uint32_t)d;

        if (di < out_len) dst[di++] = (triple >> 16) & 0xFF;
        if (di < out_len) dst[di++] = (triple >> 8) & 0xFF;
        if (di < out_len) dst[di++] = triple & 0xFF;
    }
    return di;
}

/* ------------------------------------------------------------------ */
/*  Hex encoding                                                       */
/* ------------------------------------------------------------------ */

static void bytes_to_hex(const uint8_t* src, size_t len, char* dst)
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        dst[i * 2]     = hex[src[i] >> 4];
        dst[i * 2 + 1] = hex[src[i] & 0x0F];
    }
    dst[len * 2] = '\0';
}

/* ------------------------------------------------------------------ */
/*  Minimal JSON helpers (C, strstr-based — same approach as Windows) */
/* ------------------------------------------------------------------ */

/**
 * Extract a string value from a flat JSON object by key.
 * Writes the result into dst (up to dst_len chars including null).
 * Returns the length of the extracted value (excluding null), or 0 if not found.
 */
static size_t json_get(const char* json, const char* key, char* dst, size_t dst_len)
{
    if (!json || !key || !dst || dst_len == 0) return 0;
    dst[0] = '\0';

    /* Build search string: "key" */
    char search[256];
    int slen = snprintf(search, sizeof(search), "\"%s\"", key);
    if (slen < 0 || (size_t)slen >= sizeof(search)) return 0;

    const char* pos = strstr(json, search);
    if (!pos) return 0;

    /* Find the colon after the key */
    pos += slen;
    while (*pos == ' ' || *pos == '\t' || *pos == '\n' || *pos == '\r') pos++;
    if (*pos != ':') return 0;
    pos++;
    while (*pos == ' ' || *pos == '\t' || *pos == '\n' || *pos == '\r') pos++;

    if (*pos == '"') {
        /* String value */
        pos++;
        size_t di = 0;
        while (*pos && *pos != '"') {
            char ch;
            if (*pos == '\\' && *(pos + 1)) {
                pos++;
                if (*pos == 'n') ch = '\n';
                else if (*pos == 't') ch = '\t';
                else if (*pos == '\\') ch = '\\';
                else if (*pos == '"') ch = '"';
                else ch = *pos;
            } else {
                ch = *pos;
            }
            if (di + 1 < dst_len)
                dst[di] = ch;
            di++;
            pos++;
        }
        if (di < dst_len) dst[di] = '\0';
        else dst[dst_len - 1] = '\0';
        return di;
    } else {
        /* Non-string value (number, bool, null, nested object/array) */
        size_t di = 0;
        int depth = 0;
        while (*pos) {
            if (*pos == '{' || *pos == '[') depth++;
            else if (*pos == '}' || *pos == ']') {
                if (depth == 0) break;
                depth--;
            } else if (depth == 0 && (*pos == ',' || *pos == '}')) {
                break;
            }
            if (di + 1 < dst_len)
                dst[di] = *pos;
            di++;
            pos++;
        }
        if (di < dst_len) dst[di] = '\0';
        else dst[dst_len - 1] = '\0';
        return di;
    }
}

/**
 * Build a JSON key-value pair into a buffer.
 * The value is quoted as a string. Appends to buf at *offset.
 */
static void json_append_string(char* buf, size_t buf_len, size_t* offset,
                               const char* key, const char* value, int is_first)
{
    size_t off = *offset;
    if (!is_first && off + 1 < buf_len)
        buf[off++] = ',';

    /* "key":"value" */
    int n = snprintf(buf + off, buf_len - off, "\"%s\":\"", key);
    if (n > 0) off += (size_t)n;

    /* Escape value */
    for (const char* p = value; *p && off + 2 < buf_len; p++) {
        if (*p == '"' || *p == '\\') {
            buf[off++] = '\\';
            buf[off++] = *p;
        } else if (*p == '\n') {
            buf[off++] = '\\';
            buf[off++] = 'n';
        } else {
            buf[off++] = *p;
        }
    }

    if (off + 1 < buf_len)
        buf[off++] = '"';
    buf[off] = '\0';
    *offset = off;
}

/**
 * Append a raw (unquoted) JSON value — for booleans, numbers, nested objects.
 */
static void json_append_raw(char* buf, size_t buf_len, size_t* offset,
                            const char* key, const char* raw_value, int is_first)
{
    size_t off = *offset;
    if (!is_first && off + 1 < buf_len)
        buf[off++] = ',';

    int n = snprintf(buf + off, buf_len - off, "\"%s\":%s", key, raw_value);
    if (n > 0) off += (size_t)n;
    buf[off] = '\0';
    *offset = off;
}

/* ------------------------------------------------------------------ */
/*  DER to PEM conversion                                              */
/* ------------------------------------------------------------------ */

static int der_to_pem(const uint8_t* der, size_t der_len, char* pem, size_t pem_len)
{
    const char* header = "-----BEGIN CERTIFICATE-----\n";
    const char* footer = "\n-----END CERTIFICATE-----";

    /* Compute b64 length */
    size_t b64_len = 4 * ((der_len + 2) / 3);
    size_t needed = strlen(header) + b64_len + strlen(footer) + 1;
    if (pem_len < needed) return -1;

    size_t off = 0;
    memcpy(pem + off, header, strlen(header));
    off += strlen(header);

    base64_encode(der, der_len, pem + off, pem_len - off);
    off += b64_len;

    memcpy(pem + off, footer, strlen(footer));
    off += strlen(footer);
    pem[off] = '\0';
    return 0;
}

/* ------------------------------------------------------------------ */
/*  RootHeraldEnroll                                                   */
/* ------------------------------------------------------------------ */

RootHeraldResult RootHeraldEnroll(
    const char* server_url,
    RootHeraldEnrollmentInfo* out_info)
{
    if (!server_url || !out_info)
        return RH_PROTO_ERR_INVALID_PARAM;

    memset(out_info, 0, sizeof(RootHeraldEnrollmentInfo));

    /* 1. Open TPM */
    TpmContext* tpm = tpm_open();
    if (!tpm)
        return RH_PROTO_ERR_NO_TPM;

    /* 2. Read EK certificate from NV */
    uint8_t ek_cert[4096];
    size_t ek_cert_len = sizeof(ek_cert);
    int have_ek_cert = (tpm_read_ek_cert(tpm, ek_cert, &ek_cert_len) == 0);

    /* 3. Read EK public key (CreatePrimary under ENDORSEMENT) */
    uint8_t ek_pub[1024];
    size_t ek_pub_len = sizeof(ek_pub);
    if (tpm_read_ek_pub(tpm, ek_pub, &ek_pub_len) != 0) {
        tpm_close(tpm);
        return RH_PROTO_ERR_NO_TPM;
    }

    /* 4. Create AK (SRK + AK under OWNER hierarchy) */
    if (tpm_create_ak(tpm) != 0) {
        tpm_close(tpm);
        return RH_PROTO_ERR_ENROLLMENT_FAILED;
    }

    /* 5. Get AK public area and AK name */
    uint8_t ak_pub[1024];
    size_t ak_pub_len = sizeof(ak_pub);
    if (tpm_get_ak_pub(tpm, ak_pub, &ak_pub_len) != 0) {
        tpm_close(tpm);
        return RH_PROTO_ERR_ENROLLMENT_FAILED;
    }

    uint8_t ak_name[256];
    size_t ak_name_len = sizeof(ak_name);
    if (tpm_get_ak_name(tpm, ak_name, &ak_name_len) != 0) {
        tpm_close(tpm);
        return RH_PROTO_ERR_ENROLLMENT_FAILED;
    }

    /* 6. Encode values for JSON */
    char ek_cert_pem[8192] = "";
    if (have_ek_cert)
        der_to_pem(ek_cert, ek_cert_len, ek_cert_pem, sizeof(ek_cert_pem));

    char ek_pub_b64[2048];
    base64_encode(ek_pub, ek_pub_len, ek_pub_b64, sizeof(ek_pub_b64));

    char ak_pub_b64[2048];
    base64_encode(ak_pub, ak_pub_len, ak_pub_b64, sizeof(ak_pub_b64));

    char ak_name_b64[512];
    base64_encode(ak_name, ak_name_len, ak_name_b64, sizeof(ak_name_b64));

    /* 7. Build enrollment JSON body */
    char body[16384];
    size_t off = 0;
    body[off++] = '{';
    body[off] = '\0';
    json_append_string(body, sizeof(body), &off, "ekCertPem", ek_cert_pem, 1);
    json_append_string(body, sizeof(body), &off, "ekPublicKey", ek_pub_b64, 0);
    json_append_string(body, sizeof(body), &off, "akPublicArea", ak_pub_b64, 0);
    json_append_string(body, sizeof(body), &off, "akName", ak_name_b64, 0);
    json_append_string(body, sizeof(body), &off, "platform", "linux", 0);
    if (off + 1 < sizeof(body))
        body[off++] = '}';
    body[off] = '\0';

    /* 8. POST enrollment */
    char url[2048];
    snprintf(url, sizeof(url), "%s/api/v1/devices/enroll", server_url);

    char response[8192];
    int http_code = http_post_json(url, body, response, sizeof(response));
    if (http_code != 201 && http_code != 200) {
        RH_LOG_WARN("RootHeraldEnroll: enrollment POST returned %d\n", http_code);
        tpm_close(tpm);
        return RH_PROTO_ERR_ENROLLMENT_FAILED;
    }

    /* 9. Parse response: deviceId, credentialBlob, encryptedSecret */
    char device_id[64];
    char cred_blob_b64[4096];
    char enc_secret_b64[4096];

    json_get(response, "deviceId", device_id, sizeof(device_id));
    json_get(response, "credentialBlob", cred_blob_b64, sizeof(cred_blob_b64));
    json_get(response, "encryptedSecret", enc_secret_b64, sizeof(enc_secret_b64));

    if (device_id[0] == '\0' || cred_blob_b64[0] == '\0' || enc_secret_b64[0] == '\0') {
        /* If server doesn't need credential activation, it may still have returned deviceId */
        if (device_id[0] != '\0') {
            strncpy(out_info->device_id, device_id, sizeof(out_info->device_id) - 1);
            strncpy(out_info->credential_blob, cred_blob_b64, sizeof(out_info->credential_blob) - 1);
            strncpy(out_info->encrypted_secret, enc_secret_b64, sizeof(out_info->encrypted_secret) - 1);
            tpm_close(tpm);
            return RH_PROTO_OK;
        }
        tpm_close(tpm);
        return RH_PROTO_ERR_ENROLLMENT_FAILED;
    }

    /* 10. Decode credential blob and secret */
    uint8_t cred_blob[2048];
    size_t cred_blob_len = base64_decode(cred_blob_b64, strlen(cred_blob_b64),
                                          cred_blob, sizeof(cred_blob));

    uint8_t enc_secret[2048];
    size_t enc_secret_len = base64_decode(enc_secret_b64, strlen(enc_secret_b64),
                                           enc_secret, sizeof(enc_secret));

    /* 11. ActivateCredential */
    uint8_t decrypted[256];
    size_t decrypted_len = sizeof(decrypted);

    int act_rc = tpm_activate_credential(tpm, cred_blob, cred_blob_len,
                                         enc_secret, enc_secret_len,
                                         decrypted, &decrypted_len);

    if (act_rc != 0) {
        /* Activation failed — return partial info so caller can retry */
        RH_LOG_WARN("RootHeraldEnroll: ActivateCredential failed\n");
        strncpy(out_info->device_id, device_id, sizeof(out_info->device_id) - 1);
        strncpy(out_info->credential_blob, cred_blob_b64, sizeof(out_info->credential_blob) - 1);
        strncpy(out_info->encrypted_secret, enc_secret_b64, sizeof(out_info->encrypted_secret) - 1);
        tpm_close(tpm);
        return RH_PROTO_OK; /* partial success */
    }

    /* 12. POST activation */
    char decrypted_b64[512];
    base64_encode(decrypted, decrypted_len, decrypted_b64, sizeof(decrypted_b64));

    char activate_body[8192];
    off = 0;
    activate_body[off++] = '{';
    activate_body[off] = '\0';
    json_append_string(activate_body, sizeof(activate_body), &off, "deviceId", device_id, 1);
    json_append_string(activate_body, sizeof(activate_body), &off, "decryptedSecret", decrypted_b64, 0);
    json_append_string(activate_body, sizeof(activate_body), &off, "akPublicKey", ak_pub_b64, 0);
    if (off + 1 < sizeof(activate_body))
        activate_body[off++] = '}';
    activate_body[off] = '\0';

    snprintf(url, sizeof(url), "%s/api/v1/devices/activate", server_url);

    char activate_response[4096];
    http_code = http_post_json(url, activate_body, activate_response, sizeof(activate_response));
    if (http_code != 200) {
        RH_LOG_WARN("RootHeraldEnroll: activation POST returned %d\n", http_code);
        tpm_close(tpm);
        return RH_PROTO_ERR_ENROLLMENT_FAILED;
    }

    strncpy(out_info->device_id, device_id, sizeof(out_info->device_id) - 1);
    tpm_close(tpm);
    return RH_PROTO_OK;
}

/* ------------------------------------------------------------------ */
/*  RootHeraldAttest                                                   */
/* ------------------------------------------------------------------ */

RootHeraldResult RootHeraldAttest(
    const char* server_url,
    const char* session_id,
    const char* nonce_b64,
    size_t nonce_len,
    RootHeraldAttestationInfo* out_info)
{
    if (!server_url || !session_id || !nonce_b64 || !out_info)
        return RH_PROTO_ERR_INVALID_PARAM;

    memset(out_info, 0, sizeof(RootHeraldAttestationInfo));
    (void)nonce_len; /* we decode from the b64 string directly */

    /* 1. Decode nonce from base64 */
    uint8_t nonce[256];
    size_t nonce_decoded_len = base64_decode(nonce_b64, strlen(nonce_b64),
                                              nonce, sizeof(nonce));
    if (nonce_decoded_len == 0)
        return RH_PROTO_ERR_INVALID_PARAM;

    /* 2. Open TPM */
    TpmContext* tpm = tpm_open();
    if (!tpm)
        return RH_PROTO_ERR_NO_TPM;

    /* Recreate the AK (SRK + AK) so the quote can be signed */
    if (tpm_create_ak(tpm) != 0) {
        tpm_close(tpm);
        return RH_PROTO_ERR_ATTESTATION_FAILED;
    }

    /* 3. Generate TPM Quote for standard PCRs */
    uint32_t pcr_indices[] = { 0, 1, 2, 3, 4, 7 };
    size_t pcr_count = sizeof(pcr_indices) / sizeof(pcr_indices[0]);

    uint8_t quoted[4096];
    size_t quoted_len = sizeof(quoted);
    uint8_t sig[1024];
    size_t sig_len = sizeof(sig);

    if (tpm_quote(tpm, nonce, nonce_decoded_len,
                  pcr_indices, pcr_count,
                  quoted, &quoted_len, sig, &sig_len) != 0) {
        RH_LOG_WARN("RootHeraldAttest: tpm_quote failed\n");
        tpm_close(tpm);
        return RH_PROTO_ERR_ATTESTATION_FAILED;
    }

    /* 4. Read event log */
    uint8_t event_log_buf[65536];
    int event_log_size = event_log_read(event_log_buf, sizeof(event_log_buf));
    if (event_log_size < 0) event_log_size = 0;

    /* 5. Read PCR values for selected indices */
    /* Build a JSON object: {"sha256":{"0":"<hex>","1":"<hex>",...}} */
    char pcr_json[4096];
    size_t poff = 0;
    int n = snprintf(pcr_json + poff, sizeof(pcr_json) - poff, "{\"sha256\":{");
    if (n > 0) poff += (size_t)n;

    for (size_t i = 0; i < pcr_count; i++) {
        uint8_t digest[64];
        size_t digest_len = sizeof(digest);
        char hex_val[129];

        if (tpm_pcr_read(tpm, pcr_indices[i], digest, &digest_len) == 0) {
            bytes_to_hex(digest, digest_len, hex_val);
        } else {
            /* Zero-fill on failure */
            memset(hex_val, '0', 64);
            hex_val[64] = '\0';
        }

        n = snprintf(pcr_json + poff, sizeof(pcr_json) - poff,
                     "%s\"%u\":\"%s\"",
                     (i > 0) ? "," : "",
                     pcr_indices[i], hex_val);
        if (n > 0) poff += (size_t)n;
    }

    n = snprintf(pcr_json + poff, sizeof(pcr_json) - poff, "}}");
    if (n > 0) poff += (size_t)n;
    pcr_json[poff] = '\0';

    /* 6. Encode quote, signature, event log for transport */
    char quoted_b64[8192];
    base64_encode(quoted, quoted_len, quoted_b64, sizeof(quoted_b64));

    char sig_b64[2048];
    base64_encode(sig, sig_len, sig_b64, sizeof(sig_b64));

    char event_log_b64[131072];
    if (event_log_size > 0)
        base64_encode(event_log_buf, (size_t)event_log_size,
                      event_log_b64, sizeof(event_log_b64));
    else
        event_log_b64[0] = '\0';

    /* Build the quote sub-object */
    char quote_json[16384];
    size_t qoff = 0;
    quote_json[qoff++] = '{';
    quote_json[qoff] = '\0';
    json_append_string(quote_json, sizeof(quote_json), &qoff, "quoted", quoted_b64, 1);
    json_append_string(quote_json, sizeof(quote_json), &qoff, "signature", sig_b64, 0);
    if (qoff + 1 < sizeof(quote_json))
        quote_json[qoff++] = '}';
    quote_json[qoff] = '\0';

    /* 7. Build attestation JSON body */
    char body[262144]; /* large buffer for event log */
    size_t boff = 0;
    body[boff++] = '{';
    body[boff] = '\0';
    json_append_string(body, sizeof(body), &boff, "sessionId", session_id, 1);
    json_append_raw(body, sizeof(body), &boff, "quote", quote_json, 0);
    json_append_raw(body, sizeof(body), &boff, "pcrValues", pcr_json, 0);
    json_append_string(body, sizeof(body), &boff, "eventLog", event_log_b64, 0);
    if (boff + 1 < sizeof(body))
        body[boff++] = '}';
    body[boff] = '\0';

    /* 8. POST attestation */
    char url[2048];
    snprintf(url, sizeof(url), "%s/api/v1/attest", server_url);

    char response[8192];
    int http_code = http_post_json(url, body, response, sizeof(response));
    if (http_code != 200) {
        RH_LOG_WARN("RootHeraldAttest: attest POST returned %d\n", http_code);
        tpm_close(tpm);
        return RH_PROTO_ERR_ATTESTATION_FAILED;
    }

    /* 9. Parse response */
    char status[32];
    char auth_code[128];
    char redirect_uri[2048];
    char reason[512];

    json_get(response, "status", status, sizeof(status));
    json_get(response, "authorizationCode", auth_code, sizeof(auth_code));
    json_get(response, "redirectUri", redirect_uri, sizeof(redirect_uri));
    json_get(response, "reason", reason, sizeof(reason));

    strncpy(out_info->session_id, session_id, sizeof(out_info->session_id) - 1);
    strncpy(out_info->status, status, sizeof(out_info->status) - 1);
    strncpy(out_info->authorization_code, auth_code, sizeof(out_info->authorization_code) - 1);
    strncpy(out_info->redirect_uri, redirect_uri, sizeof(out_info->redirect_uri) - 1);
    strncpy(out_info->failure_reason, reason, sizeof(out_info->failure_reason) - 1);

    tpm_close(tpm);

    if (strcmp(status, "verified") == 0)
        return RH_PROTO_OK;
    else
        return RH_PROTO_ERR_ATTESTATION_FAILED;
}

/* ------------------------------------------------------------------ */
/*  RootHeraldGetStatus                                                */
/* ------------------------------------------------------------------ */

RootHeraldResult RootHeraldGetStatus(RootHeraldDeviceStatus* out_status)
{
    if (!out_status)
        return RH_PROTO_ERR_INVALID_PARAM;

    memset(out_status, 0, sizeof(RootHeraldDeviceStatus));
    strncpy(out_status->platform, "linux", sizeof(out_status->platform) - 1);

    /* Check TPM availability */
    out_status->has_tpm = tpm_is_available();

    /* Try opening the TPM to verify functional access */
    if (out_status->has_tpm) {
        TpmContext* tpm = tpm_open();
        if (tpm) {
            /* TPM is functional */
            tpm_close(tpm);
        } else {
            /* Device node exists but ESAPI init failed */
            out_status->has_tpm = 0;
        }
    }

    /* Enrollment status: check if a device_id file exists in a well-known location */
    FILE* f = fopen("/var/lib/rootherald/device_id", "r");
    if (f) {
        out_status->is_enrolled = 1;
        size_t n = fread(out_status->device_id, 1, sizeof(out_status->device_id) - 1, f);
        out_status->device_id[n] = '\0';
        /* Strip trailing newline */
        while (n > 0 && (out_status->device_id[n - 1] == '\n' ||
                          out_status->device_id[n - 1] == '\r')) {
            out_status->device_id[--n] = '\0';
        }
        fclose(f);
    } else {
        out_status->is_enrolled = 0;
    }

    return RH_PROTO_OK;
}
