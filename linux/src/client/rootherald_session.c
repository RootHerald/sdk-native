/**
 * Root Herald — keyless enroll + local-info public ABI stubs (Linux).
 *
 * The keyless enrollment handshake (RootHeraldClient_EnrollBegin /
 * RootHeraldClient_EnrollComplete) and the local-info surface
 * (RootHeraldClient_GetDeviceInfo / RootHeraldClient_CollectPosture) are fully
 * implemented on Windows only. These stubs keep librootherald.a ABI-complete on
 * Linux until the tpm2-tss-backed implementation lands: every entry point
 * validates arguments, logs once, and returns ROOTHERALD_ERR_INTERNAL.
 */

#include "rootherald.h"
#include "log.h"

#include <string.h>

ROOTHERALD_API RootHeraldStatus RootHeraldClient_EnrollBegin(
    RootHeraldClient* client, char** out_request_json)
{
    if (out_request_json) *out_request_json = NULL;
    if (!client || !out_request_json) return ROOTHERALD_ERR_INVALID_ARG;
    RH_LOG_WARN("RootHeraldClient_EnrollBegin: not implemented on this platform yet\n");
    return ROOTHERALD_ERR_INTERNAL;
}

ROOTHERALD_API RootHeraldStatus RootHeraldClient_EnrollComplete(
    RootHeraldClient* client, const char* challenge_json, char** out_activation_json)
{
    if (out_activation_json) *out_activation_json = NULL;
    if (!client || !out_activation_json || !challenge_json || !challenge_json[0])
        return ROOTHERALD_ERR_INVALID_ARG;
    RH_LOG_WARN("RootHeraldClient_EnrollComplete: not implemented on this platform yet\n");
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
