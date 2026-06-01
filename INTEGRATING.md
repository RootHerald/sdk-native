# Integrating RootHerald into your application

This SDK ships as a **static archive** — `RootHerald.lib` (Windows),
`librootherald.a` (Linux/macOS). You link it into your own binary at
compile time. There is no runtime DLL/SO/DYLIB dependency on us, and no
service or daemon to install on the customer's machine.

Public surface: **one header**, `common/rootherald.h`. C99-compatible,
consumable from C, C++, Rust, Go, Swift, .NET P/Invoke, etc.

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

    RootHeraldClient* c = RootHeraldClient_Create("rh_pk_live_...", NULL);
    if (!c) return 1;

    RootHeraldVerifyResult r;
    RootHeraldStatus st = RootHeraldClient_Verify(c, "game-launch", &r);
    if (st == ROOTHERALD_OK) {
        printf("verdict=%d device=%s class=%s\n", r.verdict, r.device_id, r.tpm_class);
    } else {
        printf("verify failed: %s\n", RootHerald_ErrorString(st));
    }

    RootHeraldClient_Destroy(c);
    return 0;
}
```

A runnable copy of the above lives under `samples/minimal/<platform>/`.

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

No heap-allocated values cross the ABI. `RootHeraldVerifyResult` is
caller-allocated; the library only writes into it. All handles are
opaque and must be paired with `RootHeraldClient_Destroy`.

## What this SDK does NOT do

- It does not log anywhere by default. Register a callback if you want output.
- It does not call `exit()`, `abort()`, or raise signals on error. Every
  failure returns a status code.
- It does not spawn threads, allocate from custom arenas, or install
  signal handlers. It calls the platform allocator and your TPM driver.
- It does not bundle telemetry, analytics, or "phone-home" pings. The
  only network traffic is the explicit POST to your configured endpoint.

## Diagnostics

If `RootHeraldClient_Verify` returns a non-OK status:

1. `RootHerald_ErrorString(status)` for the human-readable category.
2. Register a log callback at `ROOTHERALD_LOG_DEBUG` to see the per-step
   trace (TPM init, evidence collection, HTTPS request/response).
3. On Windows, run `tools/tpm_diag.exe` to confirm the platform exposes
   a usable TPM. On Linux, ensure `/dev/tpmrm0` exists and your process
   has access.

## License

MIT. See `LICENSE`.
