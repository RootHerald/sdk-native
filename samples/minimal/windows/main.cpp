// Minimal RootHerald integration on Windows.
//
// Build (from sdk-native/):
//   cmake -B build/sample-min-win -S samples/minimal/windows -G "Visual Studio 17 2022" -A x64
//   cmake --build build/sample-min-win --config Release
//
// Run:
//   set ROOTHERALD_API_KEY=rh_pk_live_xxx
//   build\sample-min-win\Release\rh_minimal.exe
//       → one-shot Verify flow (default)
//   build\sample-min-win\Release\rh_minimal.exe --session <session_id> <nonce_b64>
//       → server-challenge session flow (Enroll + AttestSession); the session
//         id and base64 nonce come from YOUR backend's challenge endpoint
//   build\sample-min-win\Release\rh_minimal.exe --establish-key <url> <path>
//       → elevated-child hook. The SDK spawns this elevated when raw-TBS
//         credential activation is needed; hosts MUST route it before normal
//         startup (see INTEGRATING.md). Never invoked by hand.

#include <rootherald.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

static void rh_log(RootHeraldLogLevel level, const char* msg, void* /*user_data*/) {
    static const char* kLevelTag[] = { "ERR", "WRN", "INF", "DBG", "TRC" };
    std::fprintf(stderr, "[rh %s] %s\n", kLevelTag[level], msg);
}

// Server-challenge session flow: your backend created an attestation session
// and handed this device the session id + base64 nonce; we answer the
// challenge with a fresh hardware quote and print the authorization code the
// backend redeems.
static int RunSessionFlow(RootHeraldClient* client, const char* session_id,
                          const char* nonce_b64) {
    RootHeraldEnrollResult enrolled{};
    RootHeraldStatus status = RootHeraldClient_Enroll(client, /*force_reenroll=*/0, &enrolled);
    if (status != ROOTHERALD_OK) {
        std::fprintf(stderr, "Enroll failed: %s\n", RootHerald_ErrorString(status));
        return 1;
    }
    std::printf("enrolled device=%s\n", enrolled.device_id);

    RootHeraldAttestResult attested{};
    status = RootHeraldClient_AttestSession(client, session_id, nonce_b64, &attested);
    if (status != ROOTHERALD_OK) {
        std::fprintf(stderr, "AttestSession failed: %s (status=%s reason=%s)\n",
                     RootHerald_ErrorString(status), attested.status, attested.reason);
        return 1;
    }
    std::printf("session=%s status=%s authorization_code=%s\n",
                attested.session_id, attested.status, attested.authorization_code);
    if (attested.redirect_uri[0]) std::printf("redirect_uri=%s\n", attested.redirect_uri);
    return 0;
}

int main(int argc, char** argv) {
    // Hosting requirement: route the SDK's elevated-child argv to the SDK
    // before any normal startup (Windows TBS only permits credential
    // activation for an elevated caller).
    if (argc >= 4 && std::strcmp(argv[1], "--establish-key") == 0) {
        return RootHerald_RunElevatedEstablishKey(argv[2], argv[3]);
    }

    const char* api_key = std::getenv("ROOTHERALD_API_KEY");
    if (!api_key || !*api_key) {
        std::fprintf(stderr, "ROOTHERALD_API_KEY not set\n");
        return 2;
    }

    RootHerald_SetLogCallback(rh_log, nullptr);
    RootHerald_SetLogLevel(ROOTHERALD_LOG_INFO);

    RootHeraldClient* client = RootHeraldClient_Create(api_key, /*endpoint=*/nullptr);
    if (!client) {
        std::fprintf(stderr, "RootHeraldClient_Create failed\n");
        return 1;
    }

    // Local-only device status — never touches the network.
    RootHeraldDeviceInfo info{};
    if (RootHeraldClient_GetDeviceInfo(client, &info) == ROOTHERALD_OK) {
        std::printf("platform=%s has_tpm=%d is_enrolled=%d device=%s\n",
                    info.platform_name, info.has_tpm, info.is_enrolled, info.device_id);
    }

    // Session flow only when explicitly requested — the session id and nonce
    // must come from a real backend challenge, so the default standalone run
    // sticks to Verify.
    if (argc >= 4 && std::strcmp(argv[1], "--session") == 0) {
        int rc = RunSessionFlow(client, argv[2], argv[3]);
        RootHeraldClient_Destroy(client);
        return rc;
    }

    RootHeraldVerifyResult result{};
    RootHeraldStatus status = RootHeraldClient_Verify(client, "sample-launch", &result);
    if (status != ROOTHERALD_OK) {
        std::fprintf(stderr, "Verify failed: %s\n", RootHerald_ErrorString(status));
        RootHeraldClient_Destroy(client);
        return 1;
    }

    const char* verdict_name =
        result.verdict == ROOTHERALD_VERDICT_ALLOW ? "ALLOW" :
        result.verdict == ROOTHERALD_VERDICT_WARN  ? "WARN"  : "DENY";

    std::printf("verdict=%s device=%s tpm_class=%s\n",
                verdict_name, result.device_id, result.tpm_class);
    if (result.reason[0]) std::printf("reason=%s\n", result.reason);

    RootHeraldClient_Destroy(client);
    return 0;
}
