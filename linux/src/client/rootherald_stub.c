/**
 * Root Herald — stub implementation.
 *
 * Builds a librootherald.a / .lib static archive that satisfies the public C ABI
 * with canned mock data. Useful for:
 *   - CI environments without tpm2-tss / libcurl installed
 *   - Binding development (Rust, Python) on workstations without TPM hardware
 *   - Unit tests that exercise the FFI boundary
 *
 * NEVER ship this in production — RootHerald_LibraryVersionString() prefixes
 * the version with "stub-" so callers can detect it at runtime.
 *
 * ABI 3.0: keyless surface — Create() takes no args; enrollment is the
 * EnrollBegin/EnrollComplete blob handshake; per-attestation evidence is
 * CollectEvidence. The stub returns canned blobs that echo enough structure for
 * a test harness to assert round-trip wiring. No hardware, no network.
 *
 * Wave 6: this stub is built as part of librootherald.a (STATIC). No
 * symbol-export decoration is needed.
 */

#include "rootherald.h"

#include <stdlib.h>
#include <string.h>

struct RootHeraldClient {
    char  app_id[128];
    int   mock_tpm;
};

static void copy_string(char* dst, size_t cap, const char* src) {
    if (!dst || cap == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    size_t n = strlen(src);
    if (n > cap - 1) n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

/* Heap-allocate a copy of a canned JSON blob; caller frees with
 * RootHeraldClient_FreeEvidence (which is free()). */
static RootHeraldStatus emit_blob(const char* json, char** out) {
    size_t n = strlen(json) + 1;
    char* buf = (char*)malloc(n);
    if (!buf) return ROOTHERALD_ERR_INTERNAL;
    memcpy(buf, json, n);
    *out = buf;
    return ROOTHERALD_OK;
}

ROOTHERALD_API RootHeraldClient* RootHeraldClient_Create(void)
{
    RootHeraldClient* c = (RootHeraldClient*)calloc(1, sizeof(*c));
    return c;
}

ROOTHERALD_API void RootHeraldClient_Destroy(RootHeraldClient* client) { free(client); }

ROOTHERALD_API RootHeraldStatus RootHeraldClient_SetApplicationId(
    RootHeraldClient* client, const char* app_id)
{
    if (!client || !app_id) return ROOTHERALD_ERR_INVALID_ARG;
    copy_string(client->app_id, sizeof(client->app_id), app_id);
    return ROOTHERALD_OK;
}

ROOTHERALD_API RootHeraldStatus RootHeraldClient_SetMockTpm(
    RootHeraldClient* client, int mock_enabled)
{
    if (!client) return ROOTHERALD_ERR_INVALID_ARG;
    client->mock_tpm = mock_enabled ? 1 : 0;
    return ROOTHERALD_OK;
}

ROOTHERALD_API RootHeraldStatus RootHeraldClient_EnrollBegin(
    RootHeraldClient* client, char** out_request_json)
{
    /* Canned POST /devices/enroll body. Stub only — never ship. */
    if (out_request_json) *out_request_json = NULL;
    if (!client || !out_request_json) return ROOTHERALD_ERR_INVALID_ARG;
    return emit_blob(
        "{\"stub\":true,\"ekPublicKey\":\"c3R1Yi1lay1wdWI=\","
        "\"akPublicArea\":\"c3R1Yi1hay1wdWI=\",\"platform\":\"stub\"}",
        out_request_json);
}

ROOTHERALD_API RootHeraldStatus RootHeraldClient_EnrollComplete(
    RootHeraldClient* client, const char* challenge_json, char** out_activation_json)
{
    /* Canned POST /devices/activate body. Stub only — never ship. */
    if (out_activation_json) *out_activation_json = NULL;
    if (!client || !out_activation_json || !challenge_json || !challenge_json[0])
        return ROOTHERALD_ERR_INVALID_ARG;
    return emit_blob(
        "{\"stub\":true,\"deviceId\":\"00000000-0000-4000-8000-000000000stub\","
        "\"decryptedSecret\":\"c3R1Yi1zZWNyZXQ=\"}",
        out_activation_json);
}

ROOTHERALD_API RootHeraldStatus RootHeraldClient_GetDeviceInfo(
    RootHeraldClient* client, RootHeraldDeviceInfo* out_result)
{
    if (!client || !out_result) return ROOTHERALD_ERR_INVALID_ARG;
    memset(out_result, 0, sizeof(*out_result));
    out_result->is_enrolled = 1;
    out_result->has_tpm = 1;
    copy_string(out_result->device_id, sizeof(out_result->device_id),
                "00000000-0000-4000-8000-000000000stub");
    copy_string(out_result->platform_name, sizeof(out_result->platform_name), "stub");
    return ROOTHERALD_OK;
}

ROOTHERALD_API RootHeraldStatus RootHeraldClient_CollectPosture(
    RootHeraldClient* client, RootHeraldPosture* out_result)
{
    if (!client || !out_result) return ROOTHERALD_ERR_INVALID_ARG;
    memset(out_result, 0, sizeof(*out_result));
    out_result->has_tpm = 1;
    out_result->is_enrolled = 1;
    out_result->ek_cert_present = 1;
    out_result->secure_boot = 1;
    out_result->oem_keyed = 1;
    copy_string(out_result->oem_name, sizeof(out_result->oem_name), "StubOEM");
    out_result->boot_log_measurements = 42;
    out_result->boot_log_revoked = 0;
    copy_string(out_result->device_id, sizeof(out_result->device_id),
                "00000000-0000-4000-8000-000000000stub");
    copy_string(out_result->detail_json, sizeof(out_result->detail_json),
                "{\"stub\":true}");
    return ROOTHERALD_OK;
}

ROOTHERALD_API RootHeraldStatus RootHeraldClient_CollectEvidence(
    const char* nonce_b64, char** out_evidence_json)
{
    /* Per-attestation collect (keyless, handle-less). Canned mock evidence —
     * never touches hardware or the network. The blob echoes the relayed nonce
     * so a test harness can assert round-trip wiring. Caller frees via
     * RootHeraldClient_FreeEvidence. NEVER ship the stub in production. */
    if (!out_evidence_json) return ROOTHERALD_ERR_INVALID_ARG;
    *out_evidence_json = NULL;
    if (!nonce_b64 || !nonce_b64[0]) return ROOTHERALD_ERR_INVALID_ARG;

    const char* prefix = "{\"stub\":true,\"deviceId\":"
                         "\"00000000-0000-4000-8000-000000000stub\","
                         "\"quote\":{\"nonce\":\"";
    const char* suffix = "\"}}";
    size_t n = strlen(prefix) + strlen(nonce_b64) + strlen(suffix) + 1;
    char* buf = (char*)malloc(n);
    if (!buf) return ROOTHERALD_ERR_INTERNAL;
    buf[0] = '\0';
    strcat(buf, prefix);
    strcat(buf, nonce_b64);
    strcat(buf, suffix);
    *out_evidence_json = buf;
    return ROOTHERALD_OK;
}

ROOTHERALD_API void RootHeraldClient_FreeEvidence(char* evidence_json)
{
    free(evidence_json);
}

ROOTHERALD_API const char* RootHerald_AbiVersionString(void)  { return "3.0"; }
ROOTHERALD_API const char* RootHerald_LibraryVersionString(void) { return "stub-0.2.0"; }
