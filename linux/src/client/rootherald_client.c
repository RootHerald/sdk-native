/**
 * Root Herald — public C ABI implementation (Linux).
 *
 * Public ABI is declared in common/rootherald.h. This file is the facade that
 * maps RootHeraldClient_* onto the existing rootherald_linux legacy
 * implementation (tpm2-tss ESAPI + libcurl).
 *
 * ABI 3.0: the client is KEYLESS — Create takes no api_key / endpoint, and the
 * client opens no socket to RootHerald. The keyless verbs (EnrollBegin /
 * EnrollComplete in rootherald_session.c, CollectEvidence here) are honesty-
 * guarded on Linux: the non-mock path returns ROOTHERALD_ERR_INTERNAL ("not yet
 * implemented") rather than fabricating evidence, until the tpm2-tss collectors
 * land. The library is a STATIC archive; ROOTHERALD_API is an empty token.
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
    char* applicationId;
    int   mockTpm;
    pthread_mutex_t lock;
};

static const char* const kAbiVersion = "3.0";
static const char* const kLibraryVersion = "0.2.0";

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

/* ------------------------------------------------------------------ */
/* Public ABI                                                         */
/* ------------------------------------------------------------------ */

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
    free(client->applicationId);
    free(client);
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

ROOTHERALD_API RootHeraldStatus RootHeraldClient_CollectEvidence(
    const char* nonce_b64, char** out_evidence_json)
{
    /* Per-attestation collect (keyless, handle-less). No network call by
     * contract.
     *
     * TODO(linux): wire the real collector. The Linux legacy path
     * (rootherald_linux.c, tpm2-tss ESAPI) already gathers a TPM2_Quote over a
     * nonce plus EK chain for RootHeraldAttest; factor that collection portion
     * out (exactly as the Windows RootHeraldCollectEvidence does over
     * CollectEvidenceFields) so it returns the AttestationRequest-shaped
     * evidence blob WITHOUT the POST. Until then, return the same
     * not-implemented signal the other Linux keyless entry points use, so the
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
