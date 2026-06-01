// Minimal RootHerald integration on Windows.
//
// Build (from sdk-native/):
//   cmake -B build/sample-min-win -S samples/minimal/windows -G "Visual Studio 17 2022" -A x64
//   cmake --build build/sample-min-win --config Release
//
// Run:
//   set ROOTHERALD_API_KEY=rh_pk_live_xxx
//   build\sample-min-win\Release\rh_minimal.exe

#include <rootherald.h>
#include <cstdio>
#include <cstdlib>

static void rh_log(RootHeraldLogLevel level, const char* msg, void* /*user_data*/) {
    static const char* kLevelTag[] = { "ERR", "WRN", "INF", "DBG", "TRC" };
    std::fprintf(stderr, "[rh %s] %s\n", kLevelTag[level], msg);
}

int main() {
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
