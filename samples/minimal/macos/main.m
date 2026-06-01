// Minimal RootHerald integration on macOS.
//
// Build (from sdk-native/):
//   cmake -B build/sample-min-mac -S samples/minimal/macos
//   cmake --build build/sample-min-mac
//
// Run:
//   ROOTHERALD_API_KEY=rh_pk_live_xxx ./build/sample-min-mac/rh_minimal

#import <Foundation/Foundation.h>
#include <rootherald.h>
#include <stdio.h>
#include <stdlib.h>

static void rh_log(RootHeraldLogLevel level, const char* msg, void* user_data) {
    static const char* tag[] = { "ERR", "WRN", "INF", "DBG", "TRC" };
    (void)user_data;
    fprintf(stderr, "[rh %s] %s\n", tag[level], msg);
}

int main(int argc, const char* argv[]) {
    (void)argc; (void)argv;
    @autoreleasepool {
        const char* api_key = getenv("ROOTHERALD_API_KEY");
        if (!api_key || !*api_key) {
            fprintf(stderr, "ROOTHERALD_API_KEY not set\n");
            return 2;
        }

        RootHerald_SetLogCallback(rh_log, NULL);
        RootHerald_SetLogLevel(ROOTHERALD_LOG_INFO);

        RootHeraldClient* client = RootHeraldClient_Create(api_key, NULL);
        if (!client) {
            fprintf(stderr, "RootHeraldClient_Create failed\n");
            return 1;
        }

        RootHeraldVerifyResult result = {0};
        RootHeraldStatus status = RootHeraldClient_Verify(client, "sample-launch", &result);
        if (status != ROOTHERALD_OK) {
            fprintf(stderr, "Verify failed: %s\n", RootHerald_ErrorString(status));
            RootHeraldClient_Destroy(client);
            return 1;
        }

        const char* verdict_name =
            result.verdict == ROOTHERALD_VERDICT_ALLOW ? "ALLOW" :
            result.verdict == ROOTHERALD_VERDICT_WARN  ? "WARN"  : "DENY";

        printf("verdict=%s device=%s tpm_class=%s\n",
               verdict_name, result.device_id, result.tpm_class);
        if (result.reason[0]) printf("reason=%s\n", result.reason);

        RootHeraldClient_Destroy(client);
    }
    return 0;
}
