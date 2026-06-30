/**
 * Root Herald — public C ABI implementation (macOS).
 *
 * Public ABI is declared in src/clients/common/rootherald.h. Maps
 * RootHeraldClient_* onto the existing rootherald_macos legacy implementation
 * (Secure Enclave + NSURLSession).
 *
 * macOS is "reduced" assurance — no TPM, no PCRs, no Quote. The tpm_class
 * surfaced through the public ABI is "secure-enclave-reduced" so policy
 * authors and downstream consumers can fail-closed on hardware-rooted
 * deployments and fail-open on user-trust ones.
 *
 * Wave 6: librootherald is a STATIC archive on macOS. No symbol-visibility
 * decoration is required — ROOTHERALD_API is an empty token.
 */

#import <Foundation/Foundation.h>

#include "rootherald.h"
#include "rootherald_macos.h"  /* pulls protocol.h */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>

struct RootHeraldClient {
    char* api_key;
    char* endpoint;
    char* application_id;
    char  device_id[129];
    int   mock_tpm;
    pthread_mutex_t lock;
};

static const char* const kAbiVersion = "2.0";
static const char* const kLibraryVersion = "0.2.0";
static const char* const kDefaultEndpoint = "https://rootherald.io";

static char* dup_or_null(const char* s)
{
    if (!s) return NULL;
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
    copy_string(out->tpm_class, sizeof(out->tpm_class), "secure-enclave-reduced");
    copy_string(out->posture_json, sizeof(out->posture_json),
                "{\"mock\":true,\"tpm_class\":\"secure-enclave-reduced\"}");
    copy_string(out->reason, sizeof(out->reason), "mock-tpm mode");
}

ROOTHERALD_API RootHeraldClient* RootHeraldClient_Create(
    const char* api_key, const char* endpoint)
{
    if (!api_key || !api_key[0]) return NULL;
    RootHeraldClient* c = (RootHeraldClient*)calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->api_key = dup_or_null(api_key);
    c->endpoint = dup_or_null((endpoint && endpoint[0]) ? endpoint : kDefaultEndpoint);
    if (!c->api_key || !c->endpoint) {
        free(c->api_key); free(c->endpoint); free(c);
        return NULL;
    }
    pthread_mutex_init(&c->lock, NULL);
    return c;
}

ROOTHERALD_API void RootHeraldClient_Destroy(RootHeraldClient* client)
{
    if (!client) return;
    pthread_mutex_destroy(&client->lock);
    free(client->api_key);
    free(client->endpoint);
    free(client->application_id);
    free(client);
}

ROOTHERALD_API RootHeraldStatus RootHeraldClient_SetEndpoint(
    RootHeraldClient* client, const char* endpoint)
{
    if (!client || !endpoint) return ROOTHERALD_ERR_INVALID_ARG;
    pthread_mutex_lock(&client->lock);
    char* d = dup_or_null(endpoint);
    if (!d) { pthread_mutex_unlock(&client->lock); return ROOTHERALD_ERR_INTERNAL; }
    free(client->endpoint);
    client->endpoint = d;
    pthread_mutex_unlock(&client->lock);
    return ROOTHERALD_OK;
}

ROOTHERALD_API RootHeraldStatus RootHeraldClient_SetApplicationId(
    RootHeraldClient* client, const char* app_id)
{
    if (!client || !app_id) return ROOTHERALD_ERR_INVALID_ARG;
    pthread_mutex_lock(&client->lock);
    char* d = dup_or_null(app_id);
    if (!d) { pthread_mutex_unlock(&client->lock); return ROOTHERALD_ERR_INTERNAL; }
    free(client->application_id);
    client->application_id = d;
    pthread_mutex_unlock(&client->lock);
    return ROOTHERALD_OK;
}

ROOTHERALD_API RootHeraldStatus RootHeraldClient_SetMockTpm(
    RootHeraldClient* client, int mock_enabled)
{
    if (!client) return ROOTHERALD_ERR_INVALID_ARG;
    pthread_mutex_lock(&client->lock);
    client->mock_tpm = mock_enabled ? 1 : 0;
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
    if (client->mock_tpm) {
        /* Explicit, opt-in mock mode only (RootHeraldClient_SetMockTpm). This
         * returns a CANNED ALLOW and is the ONLY path on macOS that yields an
         * ALLOW today. It is not a real verdict — never enable in production. */
        fill_mock(out_result);
        pthread_mutex_unlock(&client->lock);
        return ROOTHERALD_OK;
    }

    /* HONESTY GUARD (not-yet-implemented):
     *
     * The real one-call Verify requires a SERVER-created attestation session
     * and a SERVER-issued challenge nonce, and (on macOS) server-side
     * verification of the Secure Enclave key attestation — none of which is
     * wired up here. The previous implementation fed RootHeraldAttest a
     * CLIENT-fabricated session id ("rh-verify-<action>") and a fixed client
     * nonce ("rh-verify-nonce"), which the server rejects; the Secure Enclave
     * attestation was never server-verified. So the non-mock path could never
     * return an authoritative ALLOW — it only produced a misleading DENY.
     *
     * Rather than masquerade as a real (always-failing) attestation, return a
     * clear not-implemented signal. ROOTHERALD_ERR_INTERNAL is used to mean
     * "not implemented on this platform", consistent with how rootherald.h
     * documents the unimplemented session entry points on Linux/macOS. */
    out_result->verdict = ROOTHERALD_VERDICT_DENY;
    copy_string(out_result->device_id, sizeof(out_result->device_id), client->device_id);
    copy_string(out_result->tpm_class, sizeof(out_result->tpm_class), "secure-enclave-reduced");
    copy_string(out_result->posture_json, sizeof(out_result->posture_json), "{}");
    copy_string(out_result->reason, sizeof(out_result->reason),
                "one-call Verify is not yet implemented on macOS "
                "(Secure Enclave attestation is not server-verified); use mock mode for CI only");
    pthread_mutex_unlock(&client->lock);
    return ROOTHERALD_ERR_INTERNAL;
}

ROOTHERALD_API RootHeraldStatus RootHeraldClient_CollectEvidence(
    const char* nonce_b64, char** out_evidence_json)
{
    /* Background-Check "dumb client" (contract C5, ABI 1.3). Keyless,
     * handle-less, no network call by contract.
     *
     * TODO(macos): macOS is "reduced" assurance — Secure Enclave, no TPM, no
     * PCRs, no TPM2_Quote. When the Secure Enclave evidence collector lands
     * (rootherald_macos.m), factor its collection portion out to return the
     * evidence blob WITHOUT a network call (mirroring the Windows
     * RootHeraldCollectEvidence over CollectEvidenceFields). Do NOT invent a TPM
     * quote path that does not exist here. Until the SE collector lands, return
     * the same not-implemented signal the other macOS session entry points use,
     * so the ABI stays uniform without fabricating evidence. */
    if (out_evidence_json) *out_evidence_json = NULL;
    if (!nonce_b64 || !nonce_b64[0] || !out_evidence_json)
        return ROOTHERALD_ERR_INVALID_ARG;
    return ROOTHERALD_ERR_INTERNAL; /* not implemented on macOS yet */
}

ROOTHERALD_API void RootHeraldClient_FreeEvidence(char* evidence_json)
{
    /* Caller-frees ownership; matches the Windows implementation. free(NULL) is
     * a no-op. */
    free(evidence_json);
}

ROOTHERALD_API const char* RootHerald_AbiVersionString(void)  { return kAbiVersion; }
ROOTHERALD_API const char* RootHerald_LibraryVersionString(void) { return kLibraryVersion; }
