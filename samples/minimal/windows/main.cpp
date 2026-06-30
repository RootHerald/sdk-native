// Minimal RootHerald integration on Windows.
//
// Build (from sdk-native/):
//   cmake -B build/sample-min-win -S samples/minimal/windows -G "Visual Studio 17 2022" -A x64
//   cmake --build build/sample-min-win --config Release
//
// Run:
//   set ROOTHERALD_API_KEY=rh_pk_live_xxx
//   set ROOTHERALD_ENDPOINT=https://rootherald.io   (optional; this is the default)
//   build\sample-min-win\Release\rh_minimal.exe
//       → one-shot Verify flow (default)
//   build\sample-min-win\Release\rh_minimal.exe --session <session_id> <nonce_b64>
//       → server-challenge session flow (Enroll + AttestSession)
//   build\sample-min-win\Release\rh_minimal.exe --establish-key <url> <path>
//       → elevated-worker hook (see "Windows elevation" below). Never run by hand.
//
// ── Windows elevation ──────────────────────────────────────────────────────
// First-time ENROLLMENT runs TPM2_ActivateCredential, which Windows permits only
// for an ELEVATED process. The SDK does NOT elevate on your behalf — it returns
// ROOTHERALD_ERR_ELEVATION_REQUIRED so YOU choose a strategy. This sample shows
// the "self-elevation shim": on ELEVATION_REQUIRED we re-spawn THIS exe elevated
// (one UAC) with --establish-key, which the argv guard in main() routes to
// RootHerald_RunElevatedEstablishKey. Other strategies (use the RootHerald host,
// a privileged helper/service, or check-then-skip) are in INTEGRATING.md and the
// developer portal's "Windows elevation patterns" page. A process that already
// runs elevated (e.g. a service) never hits ELEVATION_REQUIRED at all.

#include <rootherald.h>
#include <windows.h>
#include <shellapi.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#pragma comment(lib, "shell32.lib")

static void rh_log(RootHeraldLogLevel level, const char* msg, void* /*user_data*/) {
    static const char* kLevelTag[] = { "ERR", "WRN", "INF", "DBG", "TRC" };
    std::fprintf(stderr, "[rh %s] %s\n", kLevelTag[level], msg);
}

// One elevation strategy (of several): re-spawn THIS executable elevated to run
// the SDK's RootHerald_RunElevatedEstablishKey worker via the --establish-key
// argv hook. Surfaces exactly one UAC. Returns the child's exit code (0 = OK,
// non-zero = the prompt was declined or enrollment failed). `endpoint` MUST be
// the same RootHerald endpoint the unprivileged client uses, so both agree.
static int RunSelfElevationShim(const char* endpoint) {
    wchar_t exePath[MAX_PATH] = {0};
    if (!GetModuleFileNameW(NULL, exePath, MAX_PATH)) return 1;

    wchar_t tempDir[MAX_PATH] = {0};
    GetTempPathW(MAX_PATH, tempDir);
    wchar_t resultPath[MAX_PATH] = {0};
    swprintf_s(resultPath, MAX_PATH, L"%srh_sample_%lu.txt", tempDir, GetCurrentProcessId());
    DeleteFileW(resultPath);

    wchar_t urlW[1024] = {0};
    MultiByteToWideChar(CP_UTF8, 0, endpoint, -1, urlW, 1024);
    wchar_t args[1200] = {0};
    swprintf_s(args, 1200, L"--establish-key \"%s\" \"%s\"", urlW, resultPath);

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"runas";          // triggers the UAC consent prompt
    sei.lpFile = exePath;
    sei.lpParameters = args;
    sei.nShow = SW_HIDE;
    if (!ShellExecuteExW(&sei) || !sei.hProcess) {
        std::fprintf(stderr, "elevation declined or could not be shown (err=%lu)\n", GetLastError());
        return 1;
    }
    WaitForSingleObject(sei.hProcess, INFINITE);
    DWORD code = 1;
    GetExitCodeProcess(sei.hProcess, &code);
    CloseHandle(sei.hProcess);
    DeleteFileW(resultPath);
    return (int)code;
}

// Ensure the device is enrolled, applying THIS app's elevation strategy if the
// SDK reports it needs elevation. Idempotent: a returning device is already
// enrolled and this is a cheap local no-op.
static RootHeraldStatus EnsureEnrolled(RootHeraldClient* client, const char* endpoint) {
    RootHeraldEnrollResult e{};
    RootHeraldStatus st = RootHeraldClient_Enroll(client, /*force_reenroll=*/0, &e);
    if (st == ROOTHERALD_ERR_ELEVATION_REQUIRED) {
        std::fprintf(stderr, "enrollment requires elevation; requesting it (one-time)...\n");
        if (RunSelfElevationShim(endpoint) != 0) {
            return ROOTHERALD_ERR_ELEVATION_REQUIRED; // declined / failed — caller decides
        }
        // The elevated worker persisted the AK; this call now short-circuits to OK.
        st = RootHeraldClient_Enroll(client, /*force_reenroll=*/0, &e);
    }
    if (st == ROOTHERALD_OK) std::printf("enrolled device=%s\n", e.device_id);
    return st;
}

// Server-challenge session flow: your backend created an attestation session and
// handed this device the session id + base64 nonce; we answer with a fresh
// hardware quote and print the authorization code the backend redeems.
static int RunSessionFlow(RootHeraldClient* client, const char* session_id,
                          const char* nonce_b64) {
    RootHeraldAttestResult attested{};
    RootHeraldStatus status =
        RootHeraldClient_AttestSession(client, session_id, nonce_b64, &attested);
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
    // Hosting requirement: route the elevated-worker argv to the SDK before any
    // normal startup. The self-elevation shim above re-spawns this exe with these
    // args; if you choose a different elevation strategy you STILL need this hook
    // (it's how the elevated context actually performs the enrollment).
    if (argc >= 4 && std::strcmp(argv[1], "--establish-key") == 0) {
        return RootHerald_RunElevatedEstablishKey(argv[2], argv[3]);
    }

    const char* api_key = std::getenv("ROOTHERALD_API_KEY");
    if (!api_key || !*api_key) {
        std::fprintf(stderr, "ROOTHERALD_API_KEY not set\n");
        return 2;
    }
    // Resolve the endpoint once so the unprivileged client and the elevation
    // shim target the SAME server.
    const char* endpoint = std::getenv("ROOTHERALD_ENDPOINT");
    if (!endpoint || !*endpoint) endpoint = "https://rootherald.io";

    RootHerald_SetLogCallback(rh_log, nullptr);
    RootHerald_SetLogLevel(ROOTHERALD_LOG_INFO);

    RootHeraldClient* client = RootHeraldClient_Create(api_key, endpoint);
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

    // Ensure enrollment (handles elevation per this app's strategy) before any
    // flow that needs a verifiable quote. If elevation was declined we surface a
    // clear error rather than proceeding into an attestation that will fail.
    RootHeraldStatus enrolled = EnsureEnrolled(client, endpoint);
    if (enrolled != ROOTHERALD_OK) {
        std::fprintf(stderr, "cannot attest without enrollment: %s\n",
                     RootHerald_ErrorString(enrolled));
        RootHeraldClient_Destroy(client);
        return 1;
    }

    // Session flow only when explicitly requested — the session id and nonce must
    // come from a real backend challenge, so the default run sticks to Verify.
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
