/**
 * Root Herald — public C ABI implementation (macOS).
 *
 * Public ABI is declared in common/rootherald.h. Maps RootHeraldClient_* onto
 * the existing rootherald_macos legacy implementation (Secure Enclave +
 * NSURLSession).
 *
 * ABI 3.0: the client is KEYLESS — Create takes no api_key / endpoint, and the
 * client opens no socket to RootHerald. macOS is "reduced" assurance (Secure
 * Enclave, no TPM, no PCRs, no Quote); the keyless verbs are honesty-guarded —
 * the non-mock path returns ROOTHERALD_ERR_INTERNAL ("not yet implemented")
 * rather than fabricating evidence, until the Secure Enclave collectors land.
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
    char* application_id;
    int   mock_tpm;
    pthread_mutex_t lock;
};

static const char* const kAbiVersion = "3.0";
static const char* const kLibraryVersion = "0.2.0";

static char* dup_or_null(const char* s)
{
    if (!s) return NULL;
    size_t n = strlen(s);
    char* d = (char*)malloc(n + 1);
    if (!d) return NULL;
    memcpy(d, s, n + 1);
    return d;
}

ROOTHERALD_API RootHeraldClient* RootHeraldClient_Create(void)
{
    RootHeraldClient* c = (RootHeraldClient*)calloc(1, sizeof(*c));
    if (!c) return NULL;
    pthread_mutex_init(&c->lock, NULL);
    return c;
}

ROOTHERALD_API void RootHeraldClient_Destroy(RootHeraldClient* client)
{
    if (!client) return;
    pthread_mutex_destroy(&client->lock);
    free(client->application_id);
    free(client);
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

ROOTHERALD_API RootHeraldStatus RootHeraldClient_CollectEvidence(
    const char* nonce_b64, char** out_evidence_json)
{
    /* Per-attestation collect (keyless, handle-less). No network call by
     * contract.
     *
     * TODO(macos): macOS is "reduced" assurance — Secure Enclave, no TPM, no
     * PCRs, no TPM2_Quote. When the Secure Enclave evidence collector lands
     * (rootherald_macos.m), factor its collection portion out to return the
     * evidence blob WITHOUT a network call (mirroring the Windows
     * RootHeraldCollectEvidence over CollectEvidenceFields). Do NOT invent a TPM
     * quote path that does not exist here. Until the SE collector lands, return
     * the same not-implemented signal the other macOS keyless entry points use,
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
