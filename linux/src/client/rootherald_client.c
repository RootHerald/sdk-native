/**
 * Root Herald — public C ABI implementation (Linux).
 *
 * Public ABI is declared in src/clients/common/rootherald.h. This file is
 * the facade that maps RootHeraldClient_* onto the existing rootherald_linux
 * legacy implementation (tpm2-tss ESAPI + libcurl).
 *
 * Wave 6: librootherald is a STATIC archive. No symbol-visibility decoration
 * is required — ROOTHERALD_API resolves to an empty token, and the public
 * functions are plain `extern "C"`-style C linkage.
 */

#include "rootherald.h"
#include "rootherald_linux.h"  /* pulls in protocol.h with RootHeraldResult, structs */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>

/* ------------------------------------------------------------------ */
/* Internal client state                                              */
/* ------------------------------------------------------------------ */

struct RootHeraldClient {
    char* apiKey;
    char* endpoint;
    char* applicationId;
    char  deviceId[129];
    int   mockTpm;
    pthread_mutex_t lock;
};

static const char* const kAbiVersion = "2.0";
static const char* const kLibraryVersion = "0.2.0";
static const char* const kDefaultEndpoint = "https://rootherald.io";

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

static char* dup_or_null(const char* s)
{
    if (s == NULL) return NULL;
    size_t n = strlen(s);
    char* d = (char*)malloc(n + 1);
    if (!d) return NULL;
    memcpy(d, s, n + 1);
    return d;
}

static void copy_string(char* dst, size_t cap, const char* src)
{
    if (!dst || cap == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    size_t n = strlen(src);
    if (n > cap - 1) n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

/* Retained for the not-yet-landed real Verify/session flow (see the honesty
 * guard in RootHeraldClient_Verify). Marked unused so the interim
 * not-implemented build stays warning-clean. */
__attribute__((unused))
static RootHeraldStatus map_status(RootHeraldResult r)
{
    switch (r) {
    case ROOTHERALD_OK: return ROOTHERALD_OK;
    case RH_PROTO_ERR_NO_TPM: return ROOTHERALD_ERR_TPM_UNAVAILABLE;
    case RH_PROTO_ERR_NETWORK: return ROOTHERALD_ERR_NETWORK;
    case RH_PROTO_ERR_ATTESTATION_FAILED: return ROOTHERALD_ERR_SERVER;
    case RH_PROTO_ERR_ENROLLMENT_FAILED: return ROOTHERALD_ERR_SERVER;
    case RH_PROTO_ERR_NOT_ENROLLED: return ROOTHERALD_ERR_NOT_ENROLLED;
    case RH_PROTO_ERR_INVALID_PARAM: return ROOTHERALD_ERR_INVALID_ARG;
    case RH_PROTO_ERR_ALREADY_ENROLLED: return ROOTHERALD_OK;
    default: return ROOTHERALD_ERR_INTERNAL;
    }
}

static void fill_mock(RootHeraldVerifyResult* out)
{
    out->verdict = ROOTHERALD_VERDICT_ALLOW;
    copy_string(out->device_id, sizeof(out->device_id),
                "00000000-0000-4000-8000-000000000mock");
    copy_string(out->tpm_class, sizeof(out->tpm_class), "discrete-tpm");
    copy_string(out->posture_json, sizeof(out->posture_json),
                "{\"mock\":true,\"secure_boot\":true,\"tpm_class\":\"discrete-tpm\"}");
    copy_string(out->reason, sizeof(out->reason), "mock-tpm mode");
}

/* ------------------------------------------------------------------ */
/* Public ABI                                                         */
/* ------------------------------------------------------------------ */

ROOTHERALD_API RootHeraldClient* RootHeraldClient_Create(
    const char* api_key, const char* endpoint)
{
    if (!api_key || !api_key[0]) return NULL;
    RootHeraldClient* c = (RootHeraldClient*)calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->apiKey = dup_or_null(api_key);
    c->endpoint = dup_or_null((endpoint && endpoint[0]) ? endpoint : kDefaultEndpoint);
    if (!c->apiKey || !c->endpoint) {
        free(c->apiKey); free(c->endpoint); free(c);
        return NULL;
    }
    pthread_mutex_init(&c->lock, NULL);
    return c;
}

ROOTHERALD_API void RootHeraldClient_Destroy(RootHeraldClient* client)
{
    if (!client) return;
    pthread_mutex_destroy(&client->lock);
    free(client->apiKey);
    free(client->endpoint);
    free(client->applicationId);
    free(client);
}

ROOTHERALD_API RootHeraldStatus RootHeraldClient_SetEndpoint(
    RootHeraldClient* client, const char* endpoint)
{
    if (!client || !endpoint) return ROOTHERALD_ERR_INVALID_ARG;
    pthread_mutex_lock(&client->lock);
    char* dup = dup_or_null(endpoint);
    if (!dup) { pthread_mutex_unlock(&client->lock); return ROOTHERALD_ERR_INTERNAL; }
    free(client->endpoint);
    client->endpoint = dup;
    pthread_mutex_unlock(&client->lock);
    return ROOTHERALD_OK;
}

ROOTHERALD_API RootHeraldStatus RootHeraldClient_SetApplicationId(
    RootHeraldClient* client, const char* app_id)
{
    if (!client || !app_id) return ROOTHERALD_ERR_INVALID_ARG;
    pthread_mutex_lock(&client->lock);
    char* dup = dup_or_null(app_id);
    if (!dup) { pthread_mutex_unlock(&client->lock); return ROOTHERALD_ERR_INTERNAL; }
    free(client->applicationId);
    client->applicationId = dup;
    pthread_mutex_unlock(&client->lock);
    return ROOTHERALD_OK;
}

ROOTHERALD_API RootHeraldStatus RootHeraldClient_SetMockTpm(
    RootHeraldClient* client, int mock_enabled)
{
    if (!client) return ROOTHERALD_ERR_INVALID_ARG;
    pthread_mutex_lock(&client->lock);
    client->mockTpm = mock_enabled ? 1 : 0;
    pthread_mutex_unlock(&client->lock);
    return ROOTHERALD_OK;
}

ROOTHERALD_API RootHeraldStatus RootHeraldClient_Verify(
    RootHeraldClient* client, const char* action, RootHeraldVerifyResult* out_result)
{
    if (!client || !out_result) return ROOTHERALD_ERR_INVALID_ARG;
    (void)action;  /* unused until the real server-driven flow lands */
    memset(out_result, 0, sizeof(*out_result));

    pthread_mutex_lock(&client->lock);

    if (client->mockTpm) {
        /* Explicit, opt-in mock mode only (RootHeraldClient_SetMockTpm). This
         * returns a CANNED ALLOW and is the ONLY path on Linux that yields an
         * ALLOW today. It is not a real verdict — never enable in production. */
        fill_mock(out_result);
        pthread_mutex_unlock(&client->lock);
        return ROOTHERALD_OK;
    }

    /* HONESTY GUARD (not-yet-implemented):
     *
     * The real one-call Verify requires a SERVER-created attestation session
     * and a SERVER-issued challenge nonce. The Linux path cannot produce those:
     * the only attest primitive available here is RootHeraldAttest, and the
     * previous implementation fed it a CLIENT-fabricated session id
     * ("rh-verify-<action>") and a fixed client nonce ("rh-verify-nonce").
     * The server rejects such requests, so the non-mock path could never return
     * an authoritative ALLOW — it only ever produced a confusing DENY that
     * looked like a real attestation failure.
     *
     * Rather than masquerade as a real (always-failing) attestation, return a
     * clear not-implemented signal. The server-driven session flow
     * (RootHeraldClient_Enroll / RootHeraldClient_AttestSession) is the wiring
     * that still needs to land on Linux (see rootherald.h, "Session-based
     * attestation"). Until it does, one-call Verify is not functional here.
     *
     * ROOTHERALD_ERR_INTERNAL is used to mean "not implemented on this
     * platform", consistent with how rootherald.h already documents the
     * unimplemented session entry points on Linux/macOS. */
    out_result->verdict = ROOTHERALD_VERDICT_DENY;
    copy_string(out_result->device_id, sizeof(out_result->device_id), client->deviceId);
    copy_string(out_result->tpm_class, sizeof(out_result->tpm_class), "discrete-tpm");
    copy_string(out_result->posture_json, sizeof(out_result->posture_json), "{}");
    copy_string(out_result->reason, sizeof(out_result->reason),
                "one-call Verify is not yet implemented on Linux "
                "(requires the server-driven session flow); use mock mode for CI only");
    pthread_mutex_unlock(&client->lock);
    return ROOTHERALD_ERR_INTERNAL;
}

ROOTHERALD_API RootHeraldStatus RootHeraldClient_CollectEvidence(
    const char* nonce_b64, char** out_evidence_json)
{
    /* Background-Check "dumb client" (contract C5, ABI 1.3). Keyless,
     * handle-less, no network call by contract.
     *
     * TODO(linux): wire the real collector. The Linux legacy path
     * (rootherald_linux.c, tpm2-tss ESAPI) already gathers a TPM2_Quote over a
     * nonce plus EK chain for RootHeraldAttest; factor that collection portion
     * out (exactly as the Windows RootHeraldCollectEvidence does over
     * CollectEvidenceFields) so it returns the AttestationRequest-shaped
     * evidence blob WITHOUT the POST. Until then, return the same
     * not-implemented signal the other Linux session entry points use, so the
     * ABI is uniform across platforms but never fabricates evidence. */
    if (out_evidence_json) *out_evidence_json = NULL;
    if (!nonce_b64 || !nonce_b64[0] || !out_evidence_json)
        return ROOTHERALD_ERR_INVALID_ARG;
    return ROOTHERALD_ERR_INTERNAL; /* not implemented on Linux yet */
}

ROOTHERALD_API void RootHeraldClient_FreeEvidence(char* evidence_json)
{
    /* Caller-frees ownership; matches the Windows implementation so the same
     * embedder code is portable. free(NULL) is a no-op. */
    free(evidence_json);
}

ROOTHERALD_API const char* RootHerald_AbiVersionString(void)
{
    return kAbiVersion;
}

ROOTHERALD_API const char* RootHerald_LibraryVersionString(void)
{
    return kLibraryVersion;
}
