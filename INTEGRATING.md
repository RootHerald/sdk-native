# Integrating RootHerald into your application

This SDK ships as a **static archive** — `RootHerald.lib` (Windows),
`librootherald.a` (Linux/macOS). You link it into your own binary at
compile time. There is no runtime DLL/SO/DYLIB dependency on us, and no
service or daemon to install on the customer's machine.

Public surface: **one header**, `common/rootherald.h`. C99-compatible,
consumable from C, C++, Rust, Go, Swift, .NET P/Invoke, etc.

> **Keyless client (ABI 3.0).** The client holds **no RootHerald key** and opens
> **no socket to RootHerald**. It does local TPM work and emits/consumes opaque
> JSON blobs; **your backend** relays those blobs to RootHerald. The three verbs:
>   - **EnrollBegin / EnrollComplete** — one-time keyless device-key bootstrap;
>     emit the `/devices/enroll` then `/devices/activate` request bodies.
>   - **CollectEvidence** — per-attestation: a fresh quote over a backend-issued
>     nonce → an evidence blob your backend relays to `/attestations/verify`.
>   - **CollectPosture / GetDeviceInfo** — local readiness signals (never a verdict).
>
> **Platform status.** The attestation surface is **functional on Windows only**
> today (developer-dogfooded against a real TPM; not yet externally validated). On
> **Linux** and **macOS** the keyless verbs are **not yet implemented** — they
> return `ROOTHERALD_ERR_INTERNAL` ("not yet implemented") rather than fabricating
> evidence.
>
> **This is a client library: it collects evidence, it never verifies.** Token
> /verdict verification and the `rh_sk_` secret key belong to a *separate*
> component — your backend, using a server SDK (`@rootherald/node`, `sdk-go`,
> `sdk-dotnet`, `sdk-java`, `sdk-php`, `sdk-ruby` at
> https://github.com/RootHerald). Never put the `rh_sk_` secret on the device.

The library is **silent by default** — no writes to stdout/stderr unless
you register a log callback. This matches the convention set by libfido2,
libsodium, libcurl, and mbedTLS: an embedded library should not impose
log destinations on its host.

## Quickstart

```c
#include <rootherald.h>
#include <stdio.h>

static void on_log(RootHeraldLogLevel level, const char* msg, void* ud) {
    (void)level; (void)ud;
    fprintf(stderr, "[rh] %s\n", msg);  /* or hand off to spdlog / Sentry / your sink */
}

int main(void) {
    RootHerald_SetLogCallback(on_log, NULL);
    RootHerald_SetLogLevel(ROOTHERALD_LOG_INFO);

    RootHeraldClient* c = RootHeraldClient_Create();   /* keyless: no key, no endpoint */
    if (!c) return 1;

    /* Per-attestation: collect an evidence blob over a backend-issued nonce.
     * Hand the blob to YOUR backend to relay to /api/v1/attestations/verify. */
    char* evidence = NULL;
    RootHeraldStatus st = RootHeraldClient_CollectEvidence(nonce_b64, &evidence);
    if (st == ROOTHERALD_OK) {
        send_to_my_backend(evidence);   /* your channel; your backend holds rh_sk_ */
        RootHeraldClient_FreeEvidence(evidence);
    } else {
        printf("collect failed: %s\n", RootHerald_ErrorString(st));
    }

    RootHeraldClient_Destroy(c);
    return 0;
}
```

A runnable copy of the above lives under `samples/minimal/<platform>/`.

> **Platform support.** The quickstart above is fully functional on
> **Windows** only (and there only as developer-dogfooded — not yet validated
> by an external integrator). On **Linux** and **macOS** the keyless verbs are
> still **in development**: the non-mock path returns `ROOTHERALD_ERR_INTERNAL`
> ("not yet implemented") because the collectors are not wired yet.

## Enrollment (keyless, backend-relayed)

Enrollment is a one-time (or rotation) bootstrap of the device attestation key.
It is two server round-trips with a TPM op between, and the client emits/consumes
opaque blobs your backend relays — the client never POSTs and holds no key:

```c
RootHeraldClient* c = RootHeraldClient_Create();

/* Leg 1: gen AK + gather EK under a SINGLE elevation; emit the /enroll body. */
char* enroll_request = NULL;
RootHeraldStatus st = RootHeraldClient_EnrollBegin(c, &enroll_request);
if (st == ROOTHERALD_ERR_ELEVATION_REQUIRED) { /* see "Windows elevation" below */ }
/* your backend POSTs enroll_request to /api/v1/devices/enroll (rh_sk_ auth) and
 * relays back the MakeCredential challenge {deviceId,credentialBlob,encryptedSecret} */
RootHeraldClient_FreeEvidence(enroll_request);

/* Leg 2: TPM2_ActivateCredential over the challenge; emit the /activate body.
 * MUST run in the SAME (elevated, resident) process as EnrollBegin. */
char* activation = NULL;
st = RootHeraldClient_EnrollComplete(c, challenge_json, &activation);
/* your backend POSTs activation to /api/v1/devices/activate -> enrolled. */
RootHeraldClient_FreeEvidence(activation);
```

Account binding is your backend's job: it maps the verified `deviceId` (known
after leg 1) to its user. Step-up / re-attest (RFC 9470) is just calling
`RootHeraldClient_CollectEvidence` again with a fresh nonce. Key rotation is
re-running the enroll handshake.

The keyless verbs are implemented on **Windows** today (developer-dogfooded
against the real TPM; not yet externally validated). On Linux and macOS the
entry points compile and link but return `ROOTHERALD_ERR_INTERNAL`
("not implemented on this platform yet") until the per-platform collectors land.

## Pre-flight check: `RootHeraldClient_CollectPosture`

`RootHeraldClient_CollectPosture` is a **local-only** device-readiness
snapshot — it never touches the network. Use it to cheaply test whether a
device is ready to attest (TPM reachable, locally enrolled, vendor EK cert
present, Secure Boot on, known-OEM platform key, measured-boot log counts)
before spending a billable attestation (`CollectEvidence` + the backend's
`/verify`). A game launcher, for example, can gate its "Verify this device"
button on it, or surface "what will the server see?" diagnostics for free.

```c
RootHeraldPosture p;
if (RootHeraldClient_CollectPosture(c, &p) == ROOTHERALD_OK) {
    /* p.has_tpm / p.is_enrolled / p.ek_cert_present are 0/1.
     * p.secure_boot / p.oem_keyed are 1 / 0 / -1 (undetermined).
     * p.boot_log_measurements / p.boot_log_revoked are counts, -1 when
     * the TCG event log is unavailable.
     * p.detail_json carries the machine-readable snapshot. */
}
```

**Honesty rule:** these are *readiness signals*, never a verdict. The
verdict is always server-side — tenant policy and trust-anchor chain
validation are unknowable locally — so never render posture output as
"you will pass". Implemented on **Windows** today; the Linux/macOS stubs
return `ROOTHERALD_ERR_INTERNAL` like the rest of the session surface.

## Windows elevation (your choice, not ours)

First-time **enrollment** runs `TPM2_ActivateCredential`, which Windows permits
only for an **elevated** process. Attestation afterwards is unprivileged forever.

**The SDK never elevates on your behalf.** Elevation is a policy decision — how
(and whether) to acquire admin rights depends on your app, so the SDK *reports*
the need and lets you choose:

- `RootHeraldClient_EnrollBegin` (and `_EnrollComplete`) returns
  **`ROOTHERALD_ERR_ELEVATION_REQUIRED`** when the process is not elevated.
- A process that is **already elevated** (e.g. a Windows service) never sees
  that code — the TPM ops run in-process, no prompt.

### Single elevation spans EnrollBegin → EnrollComplete

The keyless handshake interleaves a network round-trip (your backend relaying the
two legs) between the two TPM ops. The transient EK+AK context that
`EnrollComplete`'s `TPM2_ActivateCredential` needs is established by
`EnrollBegin` and **cannot** be reconstructed from the persisted handle alone, so
the **same (elevated) process must stay resident from `EnrollBegin` through
`EnrollComplete`** — the one elevation spans the relay. Practically: run an
**elevated worker** that calls `EnrollBegin`, writes the request blob out over
IPC, waits for your backend's relayed challenge, then calls `EnrollComplete` and
writes the activation blob out — all in that one resident process.

### Pick a strategy

| Strategy | When | How |
|---|---|---|
| **Elevated worker** | Normal desktop apps | On `ELEVATION_REQUIRED`, spawn a small elevated worker (`ShellExecuteEx` verb `runas`, one UAC) that drives `EnrollBegin`/`EnrollComplete` and shuttles the blobs to/from your unprivileged process over a pipe/file while staying resident across the relay. |
| **Use the RootHerald host** | Browser / native-messaging integrations | Ship our `rootherald_host.exe` (it implements the elevated worker + relay plumbing). Your app does nothing native. |
| **Privileged helper / service** | Apps that already run elevated | Call `RootHeraldClient_EnrollBegin` / `_EnrollComplete` directly from the elevated context; the unprivileged side then sees the device as enrolled. |
| **Check-then-skip (degrade)** | Sandboxed / Store / locked-down apps that cannot elevate | Detect `ELEVATION_REQUIRED`, skip enrollment, and degrade gracefully (no attestation) rather than prompting. |

Per-attestation `CollectEvidence` is always **unprivileged** — only the one-time
enrollment needs elevation.

## Platform-specific notes

### Windows (`windows/`)

- Build artifact: `RootHerald.lib` (static, x64, MSVC v143+).
- System libraries the SDK links: `ncrypt`, `tbs`, `winhttp`, `bcrypt`,
  `crypt32`. These are part of every supported Windows SKU; nothing to
  ship alongside.
- Requires Windows 10 1809+ for the TPM PCP surface used by NCrypt.
- Configure: `cmake -B build -S windows -G "Visual Studio 17 2022" -A x64`
- Build the lib only: `cmake --build build --config Release --target RootHerald`
- The `tools/` executables (`test_client`, `tpm_diag`, `boot_verify`,
  `test_harness`) are diagnostics. They are **not** part of `RootHerald.lib`
  and not intended for customer redistribution.

### Linux (`linux/`)

- Build artifact: `librootherald.a` (static).
- System dependencies (link-time): `tpm2-tss` (ESAPI, tctildr, mu) and
  `libcurl`. Discovered via `pkg-config`. Distros: install `libtss2-dev`
  and `libcurl4-openssl-dev` (Debian/Ubuntu) or equivalents.
- Requires a kernel exposing `/dev/tpmrm0` (the TPM resource manager).
- Configure: `cmake -B build -S linux`
- For CI / agents without TPM hardware, pass `-DROOTHERALD_STUB=ON` —
  this builds a **stub** that returns canned mock evidence. **Never ship
  a stub build to customers.**

### macOS (`macos/`)

- Build artifact: `librootherald.a` (static).
- System frameworks (link-time): `Security.framework`, `Foundation.framework`.
  Both are part of every macOS SKU.
- Uses Secure Enclave key attestation, not TPM. Assurance level is
  reduced compared to Windows/Linux.
- Configure: `cmake -B build -S macos`
- Stub mode: `-DROOTHERALD_STUB=ON` (shares the Linux stub source).

## Repository layout

```
sdk-native/
├── common/                  # PUBLIC header — this is the entire customer-facing API
│   ├── rootherald.h
│   └── protocol.h
├── windows/
│   ├── src/                 # PRIVATE — library implementation, not exposed
│   │   ├── client/   tpm/   boot/   certs/   transport/   internal/
│   └── tools/               # NOT part of RootHerald.lib — dev diagnostics
├── linux/
│   ├── src/   tools/        # same structure
├── macos/
│   ├── src/   tools/        # same structure
└── samples/
    ├── minimal/             # The smallest possible "link + call Verify" demo per OS
    ├── unity/   unreal/     # Game-engine plugin samples
```

## Linking the static archive into your build

### CMake (recommended)

```cmake
add_subdirectory(path/to/sdk-native/windows)   # or linux / macos
target_link_libraries(your_app PRIVATE RootHerald)
```

`RootHerald`'s `INTERFACE_INCLUDE_DIRECTORIES` already exposes
`common/`, so `#include <rootherald.h>` resolves automatically. System
library dependencies (`ncrypt`/`tbs`/`winhttp` etc.) propagate
transitively via `target_link_libraries(... PUBLIC ...)`.

### MSBuild / Visual Studio

Add `RootHerald.lib` to `Linker → Input → Additional Dependencies` and
add `common/` to `C/C++ → General → Additional Include Directories`. The
system libraries (ncrypt.lib, tbs.lib, winhttp.lib, bcrypt.lib, crypt32.lib)
also need to be added — they are not auto-imported when the consumer is
not using CMake.

### Make / autotools

```make
CFLAGS  += -I path/to/sdk-native/common
LDFLAGS += path/to/librootherald.a $(pkg-config --libs tss2-esys libcurl)  # Linux
```

## ABI stability

The header carries `ROOTHERALD_ABI_VERSION_MAJOR` / `_MINOR`. The library
follows semver on this pair: a major bump is a breaking change to any
function signature, struct layout, or enum value. Minor bumps are
strictly additive. Customers should pin the SDK to a major version.

Query the runtime version with `RootHerald_LibraryVersionString()` and
`RootHerald_AbiVersionString()`.

## Thread safety

A `RootHeraldClient*` is **not** safe for concurrent use across threads.
Serialize calls behind a mutex if you share a single handle, or create
one handle per worker. The log callback registration is process-wide and
may be invoked from any thread the library does work on — your callback
implementation must be thread-safe.

## Memory ownership

Result structs (`RootHeraldDeviceInfo`, `RootHeraldPosture`) are
caller-allocated; the library only writes into them. The blob-emitting calls
(`RootHeraldClient_EnrollBegin`, `RootHeraldClient_EnrollComplete`,
`RootHeraldClient_CollectEvidence`) return a newly-allocated NUL-terminated
`char*` the **caller owns** and **must free** with
`RootHeraldClient_FreeEvidence`. All handles are opaque and must be paired with
`RootHeraldClient_Destroy`.

## What this SDK does NOT do

- It does not log anywhere by default. Register a callback if you want output.
- It does not call `exit()`, `abort()`, or raise signals on error. Every
  failure returns a status code.
- It does not spawn threads, allocate from custom arenas, or install
  signal handlers. It calls the platform allocator and your TPM driver.
- It does not bundle telemetry, analytics, or "phone-home" pings. It opens
  **no socket to RootHerald** at all — the only network it ever does is a
  best-effort fetch to TPM-vendor PKI (e.g. AMD's AIA endpoint) to complete an
  EK certificate chain. All RootHerald traffic is your backend's, not the SDK's.

## Diagnostics

If a keyless verb (`EnrollBegin` / `EnrollComplete` / `CollectEvidence`) returns
a non-OK status:

1. `RootHerald_ErrorString(status)` for the human-readable category.
2. Register a log callback at `ROOTHERALD_LOG_DEBUG` to see the per-step
   trace (TPM init, AK create / activate, evidence collection).
3. On Windows, run `tools/tpm_diag.exe` to confirm the platform exposes
   a usable TPM. On Linux, ensure `/dev/tpmrm0` exists and your process
   has access.

## License

MIT. See `LICENSE`.
