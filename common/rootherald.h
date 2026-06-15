/**
 * Root Herald — public C ABI for embeddable native SDK.
 *
 * This header is the stable, language-agnostic surface for the Root Herald
 * native SDK. It is C99-compatible (no C++ features) so it can be consumed
 * from C, C++, Rust, Go, Zig, Swift (via clang module), and P/Invoke
 * (.NET) without an intermediate shim layer.
 *
 * Transport modes (N4)
 * --------------------
 * The client distinguishes the three deployment modes purely by the URL
 * passed to RootHeraldClient_Create / RootHeraldClient_SetEndpoint:
 *   - "https://rootherald.io"            → direct
 *   - "https://attest.customer.com"      → custom domain (transparent)
 *   - "https://api.customer.com/rh-proxy" → reverse-proxy (transparent;
 *                                            the proxy forwards to us)
 *
 * The library issues identical wire traffic in all three cases. Routing
 * concerns live entirely at the endpoint operator.
 *
 * Memory ownership
 * ----------------
 * All RootHeraldClient* handles must be paired with RootHeraldClient_Destroy.
 * RootHeraldVerifyResult is a caller-allocated struct; the library only
 * writes into it. There are no heap allocations transferred across the ABI.
 *
 * Thread-safety
 * -------------
 * A RootHeraldClient* may be used from any thread, but is not safe for
 * concurrent calls from multiple threads. Serialize calls behind a mutex
 * if you need shared use.
 */

#ifndef ROOTHERALD_H
#define ROOTHERALD_H

#include <stdint.h>
#include <stddef.h>

#define ROOTHERALD_ABI_VERSION_MAJOR 1
#define ROOTHERALD_ABI_VERSION_MINOR 2

/*
 * Linkage model (Wave 6 — static library)
 * ---------------------------------------
 * The Root Herald native library ships as a *static* archive
 * (`RootHerald.lib` on Windows, `librootherald.a` on Linux, `librootherald.a`
 * inside a static framework on macOS). Customers link it into their own
 * binary at compile time, which is then signed by their own EV / Developer ID
 * certificate. There is no runtime .dll / .so / .dylib dependency on us.
 *
 * As a result there is no `__declspec(dllexport/dllimport)` decoration on
 * the public ABI: every public symbol is a plain `extern "C"` function with
 * default visibility. `ROOTHERALD_API` is retained as a backwards-compatible
 * no-op so older translation units that reference it still compile.
 *
 * The handful of cases that *do* still ship a dynamic library — the .NET
 * NuGet's `RootHerald.Native.dll`, the Node N-API `.node` addon, and the
 * Python wheel-internal shared lib — wrap this same static library themselves
 * and re-export via their host runtime's normal mechanism (P/Invoke, N-API,
 * ctypes). They do not need the public ABI to carry Windows DLL decorations.
 */
#define ROOTHERALD_API /* static linkage — no decoration */

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque client handle. */
typedef struct RootHeraldClient RootHeraldClient;

/* Result codes returned by client entry points. */
typedef enum {
    ROOTHERALD_OK = 0,
    ROOTHERALD_ERR_INVALID_ARG = 1,
    ROOTHERALD_ERR_TPM_UNAVAILABLE = 2,
    ROOTHERALD_ERR_NETWORK = 3,
    ROOTHERALD_ERR_SERVER = 4,
    ROOTHERALD_ERR_QUOTA_EXCEEDED = 5,
    ROOTHERALD_ERR_NOT_ENROLLED = 6,
    ROOTHERALD_ERR_INTERNAL = 99
} RootHeraldStatus;

/* High-level verdict returned by Verify(). */
typedef enum {
    ROOTHERALD_VERDICT_ALLOW = 0,
    ROOTHERALD_VERDICT_WARN = 1,
    ROOTHERALD_VERDICT_DENY = 2
} RootHeraldVerdict;

/* Result of RootHeraldClient_Verify. Caller-allocated; fields are
 * fixed-length null-terminated strings to avoid cross-ABI allocation. */
typedef struct {
    RootHeraldVerdict verdict;
    char device_id[129];        /* UUID or opaque, null-terminated */
    char tpm_class[64];         /* enum stringified, null-terminated */
    char posture_json[1024];    /* opaque posture blob, null-terminated */
    char reason[256];           /* human-readable reason on deny/warn */
} RootHeraldVerifyResult;

/* Result of RootHeraldClient_Enroll. Caller-allocated. */
typedef struct {
    char device_id[129];
} RootHeraldEnrollResult;

/* Result of RootHeraldClient_AttestSession. Caller-allocated. */
typedef struct {
    char session_id[64];
    char status[32];            /* "verified" | "failed" | "expired" */
    char authorization_code[128];
    char redirect_uri[2048];
    char reason[512];           /* human-readable failure reason */
} RootHeraldAttestResult;

/* Result of RootHeraldClient_GetDeviceInfo. Caller-allocated. */
typedef struct {
    int is_enrolled;
    int has_tpm;
    char device_id[129];
    char platform_name[16];     /* "windows" | "linux" | "macos" */
} RootHeraldDeviceInfo;

/* Result of RootHeraldClient_CollectPosture. Caller-allocated. */
typedef struct {
    int has_tpm;                  /* 1 = TPM 2.0 reachable */
    int is_enrolled;              /* 1 = an attestation key exists locally */
    int ek_cert_present;          /* 1 = vendor EK certificate found */
    int secure_boot;              /* 1 on, 0 off, -1 undetermined */
    int oem_keyed;                /* 1 known-OEM PK, 0 custom/unknown, -1 undetermined */
    char oem_name[64];            /* "" when unknown */
    int boot_log_measurements;    /* measured-boot entries; -1 unavailable */
    int boot_log_revoked;         /* dbx-revoked entries; -1 unavailable */
    char device_id[129];          /* deterministic local id, "" if underivable */
    char detail_json[2048];       /* machine-readable detail snapshot */
} RootHeraldPosture;

/* ------------------------------------------------------------------ */
/* Lifecycle                                                          */
/* ------------------------------------------------------------------ */

/**
 * Create a new client.
 *   api_key  : your tenant's publishable key (rh_pk_live_...). Required.
 *   endpoint : base URL. NULL means "default rootherald.io".
 * Returns NULL on out-of-memory or invalid argument.
 */
ROOTHERALD_API RootHeraldClient* RootHeraldClient_Create(
    const char* api_key,
    const char* endpoint);

/**
 * Destroy a client. Safe to call with NULL.
 */
ROOTHERALD_API void RootHeraldClient_Destroy(RootHeraldClient* client);

/* ------------------------------------------------------------------ */
/* Endpoint and config                                                */
/* ------------------------------------------------------------------ */

/**
 * Replace the endpoint URL after construction. The library treats every
 * endpoint identically — the URL distinguishes direct / custom-domain /
 * proxy mode but the wire format is the same in all three cases.
 */
ROOTHERALD_API RootHeraldStatus RootHeraldClient_SetEndpoint(
    RootHeraldClient* client,
    const char* endpoint);

/**
 * Associate this client with a logical application id (e.g. "launcher",
 * "matchmaker"). Surfaced in audit logs and per-application policy.
 */
ROOTHERALD_API RootHeraldStatus RootHeraldClient_SetApplicationId(
    RootHeraldClient* client,
    const char* app_id);

/**
 * Enable mock-TPM mode. When true, the client emits canned attestation
 * evidence and never touches real TPM / Secure-Enclave hardware. Intended
 * for headless build agents and CI; never enable in production.
 */
ROOTHERALD_API RootHeraldStatus RootHeraldClient_SetMockTpm(
    RootHeraldClient* client,
    int mock_enabled);

/* ------------------------------------------------------------------ */
/* Verify operation                                                   */
/* ------------------------------------------------------------------ */

/**
 * Collect fresh attestation evidence and obtain a server-authoritative verdict.
 *   action       : the relying-party-defined action being authorized
 *                  (e.g. "game-launch", "transfer-funds"). NULL → "default".
 *   out_result   : caller-allocated; fields are populated on ROOTHERALD_OK.
 *
 * Returns ROOTHERALD_OK iff the server returned an authoritative verdict.
 * Network and server errors return distinct codes so the caller can
 * fail-open or fail-closed per policy.
 *
 * PLATFORM SUPPORT (important): this one-call flow is functional only on
 * Windows today. On Linux and macOS it is NOT yet wired to the real server
 * protocol (which requires a server-created session and server-issued nonce);
 * the non-mock path returns ROOTHERALD_ERR_INTERNAL with a "not yet
 * implemented" reason instead of a verdict. The mock path
 * (RootHeraldClient_SetMockTpm) returns a canned ALLOW for CI only — never a
 * real verdict.
 */
ROOTHERALD_API RootHeraldStatus RootHeraldClient_Verify(
    RootHeraldClient* client,
    const char* action,
    RootHeraldVerifyResult* out_result);

/* ------------------------------------------------------------------ */
/* Session-based attestation (server-challenge flow)                  */
/* ------------------------------------------------------------------ */
/*
 * The session flow is the server-driven counterpart to Verify(): your
 * backend creates an attestation session (and challenge nonce) with the
 * Root Herald API, hands the session id + nonce to the device, and the
 * device answers the challenge with a fresh hardware quote. On success
 * the result carries an authorization code your backend redeems.
 *
 * Every enroll/activate/attest request issued by these entry points
 * carries the handle's publishable key as the `X-RootHerald-Site-Key`
 * header so the attestation is attributed to your tenant.
 *
 * Currently fully implemented on Windows. On Linux and macOS these
 * entry points compile and link but return ROOTHERALD_ERR_INTERNAL
 * until the per-platform implementations land.
 */

/**
 * Ensure this device is enrolled with the endpoint configured on the client.
 * ALREADY_ENROLLED is mapped to ROOTHERALD_OK (out->device_id still filled).
 *   force_reenroll : 0 keeps an existing enrollment; non-zero rotates the
 *                    attestation key and re-enrolls.
 */
ROOTHERALD_API RootHeraldStatus RootHeraldClient_Enroll(
    RootHeraldClient* client,
    int force_reenroll,
    RootHeraldEnrollResult* out_result);

/**
 * Server-challenge attestation: TPM quote over nonce for an existing session.
 * nonce_b64 is a null-terminated base64 string (no separate length param).
 */
ROOTHERALD_API RootHeraldStatus RootHeraldClient_AttestSession(
    RootHeraldClient* client,
    const char* session_id,
    const char* nonce_b64,
    RootHeraldAttestResult* out_result);

/**
 * One-shot link token consumed by the next AttestSession on this handle.
 * Binds that attestation to a user account. Pass NULL to clear a pending
 * token.
 */
ROOTHERALD_API RootHeraldStatus RootHeraldClient_SetLinkToken(
    RootHeraldClient* client,
    const char* link_token);

/**
 * Local device/TPM status; never touches the network.
 */
ROOTHERALD_API RootHeraldStatus RootHeraldClient_GetDeviceInfo(
    RootHeraldClient* client,
    RootHeraldDeviceInfo* out_result);

/**
 * LOCAL-ONLY device-readiness snapshot: never touches the network.
 *
 * Collects everything the device can know about itself without a server
 * round-trip — TPM reachability, local enrollment, EK certificate
 * presence, Secure Boot state, OEM platform-key identity, and measured-
 * boot log counts. This is the free pre-flight check: call it cheaply
 * (e.g. from a game launcher) before spending a billable Verify /
 * AttestSession.
 *
 * Honesty rule: these are READINESS SIGNALS, not a verdict — the verdict
 * is always server-side (tenant policy + trust-anchor chain validation),
 * and is unknowable locally. Never render these signals as "you will
 * pass".
 *
 * Tri-state ints (secure_boot / oem_keyed) use -1 for "undetermined"
 * (e.g. the TCG event log was unavailable); count fields use -1 for
 * "unavailable".
 */
ROOTHERALD_API RootHeraldStatus RootHeraldClient_CollectPosture(
    RootHeraldClient* client,
    RootHeraldPosture* out_result);

/**
 * Elevated-child entry for the Windows TBS activation fallback (public
 * re-export of the legacy RootHeraldRunElevatedEstablishKey). Hosts MUST
 * route `--establish-key <url> <path>` argv here before normal startup;
 * documented in INTEGRATING.md. Returns 0 on success.
 */
ROOTHERALD_API int RootHerald_RunElevatedEstablishKey(
    const char* server_url,
    const char* result_path);

/* ------------------------------------------------------------------ */
/* Logging                                                            */
/* ------------------------------------------------------------------ */
/*
 * The library is silent by default — no writes to stdout/stderr unless the
 * customer explicitly registers a callback. This matches the precedent set
 * by libfido2, libsodium, libcurl, and mbedTLS: a library embedded in a
 * customer's binary should not impose log destinations on its host.
 *
 * Customers wire their preferred logger (spdlog, log4cpp, Sentry SDK, etc.)
 * by registering a callback. Filtering happens internally: messages above
 * the configured max level are dropped before any formatting work, so
 * production builds can leave callbacks installed at ERROR without paying
 * for TRACE-level message construction.
 */

typedef enum {
    ROOTHERALD_LOG_ERROR = 0,
    ROOTHERALD_LOG_WARN  = 1,
    ROOTHERALD_LOG_INFO  = 2,
    ROOTHERALD_LOG_DEBUG = 3,
    ROOTHERALD_LOG_TRACE = 4
} RootHeraldLogLevel;

/**
 * Receives a single formatted log message from the library. The `message`
 * pointer is null-terminated and owned by the library; copy if you need to
 * retain it past the call. `user_data` is whatever was passed to
 * RootHerald_SetLogCallback. The callback may be invoked from any thread
 * the library does work on; implementations should be thread-safe.
 */
typedef void (*RootHeraldLogCallback)(
    RootHeraldLogLevel level,
    const char* message,
    void* user_data);

/**
 * Register a log callback. Pass NULL to disable logging entirely (default).
 * Replaces any prior registration. Pass `user_data` to receive an arbitrary
 * context pointer on every invocation; the library does not interpret it.
 *
 * Process-wide; not per-handle. Safe to call before any RootHeraldClient
 * exists.
 */
ROOTHERALD_API void RootHerald_SetLogCallback(
    RootHeraldLogCallback callback,
    void* user_data);

/**
 * Set the maximum log level the library will emit. Defaults to
 * ROOTHERALD_LOG_WARN. Messages with level > max_level are dropped before
 * formatting, so this is the cheap way to gate verbose logging in
 * production while keeping the callback registered.
 */
ROOTHERALD_API void RootHerald_SetLogLevel(RootHeraldLogLevel max_level);

/* ------------------------------------------------------------------ */
/* Utility                                                            */
/* ------------------------------------------------------------------ */

/**
 * Returns a human-readable, English string describing a status code.
 * The pointer is owned by the library and remains valid for the process
 * lifetime. Useful for surfacing failures to logs without a switch
 * statement on every call site.
 */
ROOTHERALD_API const char* RootHerald_ErrorString(RootHeraldStatus status);

/**
 * Returns the ABI version as a static "MAJOR.MINOR" string. The pointer
 * is owned by the library and remains valid for the process lifetime.
 */
ROOTHERALD_API const char* RootHerald_AbiVersionString(void);

/**
 * Returns the library build version (semver) as a static null-terminated
 * string. Same ownership rules as RootHerald_AbiVersionString().
 */
ROOTHERALD_API const char* RootHerald_LibraryVersionString(void);

#ifdef __cplusplus
}
#endif

#endif /* ROOTHERALD_H */
