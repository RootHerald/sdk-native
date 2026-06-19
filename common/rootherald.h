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
#define ROOTHERALD_ABI_VERSION_MINOR 4

/*
 * ABI changelog
 * -------------
 * 1.4 — ADDED RootHeraldClient_EnrollCollect + RootHeraldClient_EnrollActivate
 *       (Background-Check page-driven enrollment, contract C-enroll). Additive
 *       only; every 1.3 symbol is unchanged. These are the TPM-only halves of
 *       the two-round-trip enroll ceremony with the NETWORK boundary removed:
 *       keyless and network-free, exactly like the 1.3 collect pair. The page
 *       RELAYS the two server round-trips (POST /devices/enroll then
 *       /devices/activate) through the CUSTOMER's server (WP4 Option A); the
 *       client never POSTs to RootHerald on this path. EnrollCollect returns the
 *       /enroll request body; the page posts it and hands the server's
 *       MakeCredential challenge to EnrollActivate, which returns the /activate
 *       request body. Both buffers are caller-owned and freed with the existing
 *       RootHeraldClient_FreeEvidence (a generic char* free). The key-bearing
 *       RootHeraldClient_Enroll stays for non-browser embedders that POST direct.
 * 1.3 — ADDED RootHeraldClient_CollectEvidence + RootHeraldClient_FreeEvidence
 *       (Background-Check "dumb client", contract C5). Additive only; every
 *       1.2 symbol is unchanged. Collect-only: NO API/site key required and NO
 *       RootHerald network call — returns the self-contained evidence blob to
 *       the embedder, who hands it to the CUSTOMER's server (which relays it
 *       server→server to POST /api/v1/attestations/verify). The existing
 *       key-bearing Create / AttestSession / Verify entry points remain for the
 *       Passport / "badge" tier (backend-less customers that POST directly to
 *       RootHerald with a publishable key).
 * 1.2 — RootHeraldClient_CollectPosture (local-only readiness snapshot).
 */

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

/* ------------------------------------------------------------------ */
/* Background-Check collect-only (contract C5, ABI 1.3)               */
/* ------------------------------------------------------------------ */
/*
 * The "dumb client" surface for the RATS Background-Check model. The on-device
 * client collects a self-contained evidence blob and returns it to the embedder
 * — it makes NO RootHerald network call and needs NO API/site key. The embedder
 * hands the blob to the CUSTOMER's own server, which relays it server→server
 * (authenticated with its rh_sk_ secret key) to
 * `POST /api/v1/attestations/verify`, where RootHerald appraises it and returns
 * a verdict.
 *
 * This is the privacy-/liability-preferred default: no client-side secret can
 * leak, and the customer's server is the trust boundary. The key-bearing
 * Passport entry points (RootHeraldClient_Create / _AttestSession / _Verify)
 * stay for the backend-less "badge" tier, which cannot hold a secret key in a
 * browser and so POSTs to RootHerald directly with a publishable key.
 */

/**
 * Collect attestation evidence WITHOUT contacting RootHerald and WITHOUT
 * requiring an API key.
 *
 *   nonce_b64         : the server-issued challenge nonce (base64, NUL-
 *                       terminated) the customer obtained from
 *                       `POST /api/v1/attestations/challenge` and relayed to
 *                       this client. The TPM quote is taken OVER this nonce, so
 *                       freshness / anti-replay is preserved end-to-end exactly
 *                       as on the direct path (the nonce is bound inside the
 *                       signature). Required.
 *   out_evidence_json : on ROOTHERALD_OK, receives a newly-allocated,
 *                       NUL-terminated JSON string — the self-contained evidence
 *                       blob. This is EXACTLY the object the server's
 *                       `/attestations/verify` expects in its `evidence` field
 *                       (the same AttestationRequest-shaped payload the collector
 *                       produces for the Passport `/attest` POST, MINUS the
 *                       Passport-only `sessionId` / `linkToken` fields). The
 *                       customer's server forwards it verbatim. The caller OWNS
 *                       the buffer and MUST free it with
 *                       RootHeraldClient_FreeEvidence. Set to NULL on any error.
 *
 * No RootHeraldClient_Create api_key is consulted — this call collects only.
 * Returns ROOTHERALD_OK on success; ROOTHERALD_ERR_NOT_ENROLLED if no enrolled
 * attestation key exists on the device; ROOTHERALD_ERR_TPM_UNAVAILABLE /
 * ROOTHERALD_ERR_SERVER on a TPM / quote failure; ROOTHERALD_ERR_INVALID_ARG on
 * a bad argument.
 *
 * PLATFORM SUPPORT: functional on Windows. Linux and macOS declare the entry
 * point (so the ABI is uniform) but return ROOTHERALD_ERR_INTERNAL until their
 * per-platform collectors land — consistent with the other session entry points.
 */
ROOTHERALD_API RootHeraldStatus RootHeraldClient_CollectEvidence(
    const char* nonce_b64,
    char** out_evidence_json);

/**
 * Free an evidence buffer returned by RootHeraldClient_CollectEvidence. Safe to
 * call with NULL. Pairs with the caller-frees ownership of out_evidence_json.
 * Also frees the enroll/activate buffers returned by the ABI 1.4 page-driven
 * enrollment pair below — it is a generic char* deallocator.
 */
ROOTHERALD_API void RootHeraldClient_FreeEvidence(char* evidence_json);

/* ------------------------------------------------------------------ */
/* Background-Check page-driven enrollment (contract C-enroll, ABI 1.4) */
/* ------------------------------------------------------------------ */
/*
 * The enroll ceremony is irreducibly TWO server round-trips with a TPM op
 * between: (1) collect EK pub + EK cert chain + create an AK -> POST
 * /api/v1/devices/enroll -> the server validates the EK chain, enforces the AK
 * template, and MakeCredential-seals a secret to the EK, returning a challenge
 * blob; (2) TPM2_ActivateCredential(challenge) decrypts the secret -> POST
 * /api/v1/devices/activate -> the server constant-time compares the secret and
 * Name-match guards the bound AK -> enrolled.
 *
 * These two entry points are the TPM-only halves with the NETWORK boundary
 * removed — keyless and network-free, exactly like RootHeraldClient_CollectEvidence.
 * The page RELAYS the two round-trips through the CUSTOMER's server (which
 * authenticates to RootHerald with its rh_sk_ secret key — WP4 Option A); the
 * client makes NO RootHerald network call and consults NO API/site key, so a
 * RootHeraldClient* handle is NOT required.
 *
 * SECURITY: this moves only the network boundary. The EK-chain validation, the
 * AkTemplateValidator (closes the software-AK spoofing attack), MakeCredential
 * sealing, the constant-time secret compare, and the activate Name-match guard
 * ALL still run server-side on the relayed bytes — and the relay is byte-exact,
 * so it weakens none of them.
 *
 * PLATFORM SUPPORT: functional on Windows (PCP backend — unprivileged credential
 * activation, no UAC). Linux/macOS declare the symbols for ABI uniformity but
 * return ROOTHERALD_ERR_INTERNAL until their collectors land, consistent with
 * the other session entry points.
 */

/**
 * Collect EK pub + EK cert chain + create (and persist) an AK; return the exact
 * JSON body for POST /api/v1/devices/enroll. Makes NO network call and needs NO
 * API/site key.
 *
 *   out_enroll_json : on ROOTHERALD_OK, receives a newly-allocated, NUL-
 *                     terminated JSON string — the verbatim /enroll request body
 *                     ({ekPublicKey, akPublicArea, platform, optional ekCertPem,
 *                     optional ekCertificateChain}). The customer's server posts
 *                     it to RootHerald and relays the MakeCredential challenge
 *                     back to RootHeraldClient_EnrollActivate. Caller OWNS the
 *                     buffer; free with RootHeraldClient_FreeEvidence. NULL on error.
 *
 * Returns ROOTHERALD_OK on success; ROOTHERALD_ERR_TPM_UNAVAILABLE /
 * ROOTHERALD_ERR_SERVER on a TPM / AK-creation failure; ROOTHERALD_ERR_INVALID_ARG
 * on a bad argument.
 */
ROOTHERALD_API RootHeraldStatus RootHeraldClient_EnrollCollect(
    char** out_enroll_json);

/**
 * TPM2_ActivateCredential over the server's MakeCredential challenge; return the
 * exact JSON body for POST /api/v1/devices/activate. Makes NO network call and
 * needs NO API/site key.
 *
 *   challenge_json    : the verbatim JSON the server returned from /enroll
 *                       ({deviceId, credentialBlob, encryptedSecret}), relayed by
 *                       the page. Required.
 *   out_activate_json : on ROOTHERALD_OK, receives a newly-allocated, NUL-
 *                       terminated JSON string — the verbatim /activate request
 *                       body ({deviceId, decryptedSecret}). The genuine client
 *                       sends NO akPublicKey here; the server verifies against the
 *                       AK Name MakeCredential bound at enroll. Caller OWNS the
 *                       buffer; free with RootHeraldClient_FreeEvidence. NULL on error.
 *
 * Returns ROOTHERALD_OK on success; ROOTHERALD_ERR_NOT_ENROLLED if no AK from a
 * prior EnrollCollect is present; ROOTHERALD_ERR_SERVER if ActivateCredential
 * fails; ROOTHERALD_ERR_INVALID_ARG on a bad/incomplete challenge.
 */
ROOTHERALD_API RootHeraldStatus RootHeraldClient_EnrollActivate(
    const char* challenge_json,
    char** out_activate_json);

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
