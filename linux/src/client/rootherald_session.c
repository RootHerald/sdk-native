/**
 * Root Herald — session-flow public ABI stubs (Linux).
 *
 * The session-based attestation surface (RootHeraldClient_Enroll /
 * RootHeraldClient_AttestSession / RootHeraldClient_SetLinkToken /
 * RootHeraldClient_GetDeviceInfo / RootHeraldClient_CollectPosture /
 * RootHerald_RunElevatedEstablishKey) is fully implemented on Windows
 * only. These stubs keep librootherald.a ABI-complete on Linux until the
 * tpm2-tss-backed implementation lands: every entry point validates
 * arguments, logs once, and returns ROOTHERALD_ERR_INTERNAL.
 */

#include "rootherald.h"
#include "log.h"

#include <string.h>

ROOTHERALD_API RootHeraldStatus RootHeraldClient_Enroll(
    RootHeraldClient* client, int force_reenroll, RootHeraldEnrollResult* out_result)
{
    (void)force_reenroll;
    if (!client || !out_result) return ROOTHERALD_ERR_INVALID_ARG;
    memset(out_result, 0, sizeof(*out_result));
    RH_LOG_WARN("RootHeraldClient_Enroll: not implemented on this platform yet\n");
    return ROOTHERALD_ERR_INTERNAL;
}

ROOTHERALD_API RootHeraldStatus RootHeraldClient_AttestSession(
    RootHeraldClient* client, const char* session_id, const char* nonce_b64,
    RootHeraldAttestResult* out_result)
{
    if (!client || !out_result || !session_id || !session_id[0] ||
        !nonce_b64 || !nonce_b64[0])
        return ROOTHERALD_ERR_INVALID_ARG;
    memset(out_result, 0, sizeof(*out_result));
    RH_LOG_WARN("RootHeraldClient_AttestSession: not implemented on this platform yet\n");
    return ROOTHERALD_ERR_INTERNAL;
}

ROOTHERALD_API RootHeraldStatus RootHeraldClient_SetLinkToken(
    RootHeraldClient* client, const char* link_token)
{
    (void)link_token;
    if (!client) return ROOTHERALD_ERR_INVALID_ARG;
    RH_LOG_WARN("RootHeraldClient_SetLinkToken: not implemented on this platform yet\n");
    return ROOTHERALD_ERR_INTERNAL;
}

ROOTHERALD_API RootHeraldStatus RootHeraldClient_GetDeviceInfo(
    RootHeraldClient* client, RootHeraldDeviceInfo* out_result)
{
    if (!client || !out_result) return ROOTHERALD_ERR_INVALID_ARG;
    memset(out_result, 0, sizeof(*out_result));
    RH_LOG_WARN("RootHeraldClient_GetDeviceInfo: not implemented on this platform yet\n");
    return ROOTHERALD_ERR_INTERNAL;
}

ROOTHERALD_API RootHeraldStatus RootHeraldClient_CollectPosture(
    RootHeraldClient* client, RootHeraldPosture* out_result)
{
    if (!client || !out_result) return ROOTHERALD_ERR_INVALID_ARG;
    memset(out_result, 0, sizeof(*out_result));
    RH_LOG_WARN("RootHeraldClient_CollectPosture: not implemented on this platform yet\n");
    return ROOTHERALD_ERR_INTERNAL;
}

ROOTHERALD_API int RootHerald_RunElevatedEstablishKey(
    const char* server_url, const char* result_path)
{
    (void)server_url;
    (void)result_path;
    RH_LOG_WARN("RootHerald_RunElevatedEstablishKey: not implemented on this platform yet\n");
    return ROOTHERALD_ERR_INTERNAL;
}
