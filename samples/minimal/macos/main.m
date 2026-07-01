// Minimal RootHerald integration on macOS (ABI 3.0 — keyless client).
//
// Build (from sdk-native/):
//   cmake -B build/sample-min-mac -S samples/minimal/macos
//   cmake --build build/sample-min-mac
//
// Run:
//   ./build/sample-min-mac/rh_minimal
//
// The client holds no RootHerald key and opens no socket to RootHerald — it does
// local Secure Enclave work and emits opaque blobs your backend relays. On macOS
// the keyless verbs are not yet implemented (the non-mock path returns
// ROOTHERALD_ERR_INTERNAL); see INTEGRATING.md for platform status.

#import <Foundation/Foundation.h>
#include <rootherald.h>
#include <stdio.h>

static void rh_log(RootHeraldLogLevel level, const char* msg, void* user_data) {
    static const char* tag[] = { "ERR", "WRN", "INF", "DBG", "TRC" };
    (void)user_data;
    fprintf(stderr, "[rh %s] %s\n", tag[level], msg);
}

int main(int argc, const char* argv[]) {
    (void)argc; (void)argv;
    @autoreleasepool {
        RootHerald_SetLogCallback(rh_log, NULL);
        RootHerald_SetLogLevel(ROOTHERALD_LOG_INFO);

        RootHeraldClient* client = RootHeraldClient_Create();
        if (!client) {
            fprintf(stderr, "RootHeraldClient_Create failed\n");
            return 1;
        }

        // PreCheck: local readiness snapshot (signals, never a verdict).
        RootHeraldPosture posture = {0};
        RootHeraldStatus st = RootHeraldClient_CollectPosture(client, &posture);
        if (st == ROOTHERALD_OK) {
            printf("posture: tpm=%d enrolled=%d ek_cert=%d\n",
                   posture.has_tpm, posture.is_enrolled, posture.ek_cert_present);
        } else {
            printf("CollectPosture: %s\n", RootHerald_ErrorString(st));
        }

        // Enroll, leg 1: emit the /devices/enroll request blob for your backend.
        char* enroll_request = NULL;
        st = RootHeraldClient_EnrollBegin(client, &enroll_request);
        if (st == ROOTHERALD_OK && enroll_request) {
            printf("enroll-begin (relay to POST /api/v1/devices/enroll):\n%s\n", enroll_request);
            RootHeraldClient_FreeEvidence(enroll_request);
        } else {
            printf("EnrollBegin: %s\n", RootHerald_ErrorString(st));
        }

        RootHeraldClient_Destroy(client);
    }
    return 0;
}
