// Minimal RootHerald integration on Windows (ABI 3.0 — keyless client).
//
// Build (from sdk-native/):
//   cmake -B build/sample-min-win -S samples/minimal/windows -G "Visual Studio 17 2022" -A x64
//   cmake --build build/sample-min-win --config Release
//
// Run:
//   build\sample-min-win\Release\rh_minimal.exe
//       → local device info + posture (PreCheck), then emit the enroll-begin blob
//   build\sample-min-win\Release\rh_minimal.exe --collect <nonce_b64>
//       → emit the per-attestation evidence blob for the given backend nonce
//
// ── The keyless model ───────────────────────────────────────────────────────
// The client holds NO RootHerald key and opens NO socket to RootHerald. It does
// local TPM work and hands OPAQUE JSON BLOBS to you; YOUR BACKEND (a server SDK
// authenticated with its rh_sk_) relays them to RootHerald:
//   - EnrollBegin()    -> /devices/enroll request blob   -> backend POSTs it
//   - EnrollComplete(challenge) -> /devices/activate blob -> backend POSTs it
//   - CollectEvidence(nonce) -> evidence blob            -> backend POSTs /verify
//
// ── Windows elevation + single-elevation span ───────────────────────────────
// EnrollBegin (raw-TBS AK creation) and EnrollComplete (TPM2_ActivateCredential)
// require an ELEVATED process, and the SAME process must stay resident across the
// two calls (the transient EK+AK context EnrollComplete needs lives only in the
// process that called EnrollBegin). The SDK never elevates on your behalf — it
// returns ROOTHERALD_ERR_ELEVATION_REQUIRED so you choose a strategy (run an
// elevated worker that emits the begin blob over IPC, waits for your backend's
// relayed challenge, then calls complete). See INTEGRATING.md.

#include <rootherald.h>
#include <cstdio>
#include <cstring>

static void rh_log(RootHeraldLogLevel level, const char* msg, void* /*user_data*/) {
    static const char* kLevelTag[] = { "ERR", "WRN", "INF", "DBG", "TRC" };
    std::fprintf(stderr, "[rh %s] %s\n", kLevelTag[level], msg);
}

int main(int argc, char** argv) {
    RootHerald_SetLogCallback(rh_log, nullptr);
    RootHerald_SetLogLevel(ROOTHERALD_LOG_INFO);

    RootHeraldClient* client = RootHeraldClient_Create();
    if (!client) {
        std::fprintf(stderr, "RootHeraldClient_Create failed\n");
        return 1;
    }

    // --collect <nonce_b64>: emit a per-attestation evidence blob for your backend.
    if (argc >= 3 && std::strcmp(argv[1], "--collect") == 0) {
        char* evidence = nullptr;
        RootHeraldStatus st = RootHeraldClient_CollectEvidence(argv[2], &evidence);
        if (st != ROOTHERALD_OK || !evidence) {
            std::fprintf(stderr, "CollectEvidence failed: %s\n", RootHerald_ErrorString(st));
            RootHeraldClient_Destroy(client);
            return 1;
        }
        std::printf("evidence (relay to POST /api/v1/attestations/verify):\n%s\n", evidence);
        RootHeraldClient_FreeEvidence(evidence);
        RootHeraldClient_Destroy(client);
        return 0;
    }

    // Local-only device info — never touches the network.
    RootHeraldDeviceInfo info{};
    if (RootHeraldClient_GetDeviceInfo(client, &info) == ROOTHERALD_OK) {
        std::printf("platform=%s has_tpm=%d is_enrolled=%d device=%s\n",
                    info.platform_name, info.has_tpm, info.is_enrolled, info.device_id);
    }

    // PreCheck: local readiness snapshot (signals, never a verdict).
    RootHeraldPosture posture{};
    if (RootHeraldClient_CollectPosture(client, &posture) == ROOTHERALD_OK) {
        std::printf("posture: tpm=%d enrolled=%d ek_cert=%d secure_boot=%d oem_keyed=%d (%s)\n",
                    posture.has_tpm, posture.is_enrolled, posture.ek_cert_present,
                    posture.secure_boot, posture.oem_keyed, posture.oem_name);
    }

    // Enroll, leg 1: emit the /devices/enroll request blob. Your backend relays
    // it, gets a MakeCredential challenge, and feeds it to EnrollComplete IN THIS
    // SAME (elevated, resident) process. Requires elevation.
    char* enroll_request = nullptr;
    RootHeraldStatus st = RootHeraldClient_EnrollBegin(client, &enroll_request);
    if (st == ROOTHERALD_ERR_ELEVATION_REQUIRED) {
        std::fprintf(stderr,
            "enrollment requires an elevated, resident process (see the elevation\n"
            "note at the top of this file and INTEGRATING.md)\n");
    } else if (st == ROOTHERALD_OK && enroll_request) {
        std::printf("enroll-begin (relay to POST /api/v1/devices/enroll):\n%s\n", enroll_request);
        std::printf("[next: relay the challenge back to EnrollComplete in THIS process]\n");
        RootHeraldClient_FreeEvidence(enroll_request);
    } else {
        std::fprintf(stderr, "EnrollBegin failed: %s\n", RootHerald_ErrorString(st));
    }

    RootHeraldClient_Destroy(client);
    return 0;
}
