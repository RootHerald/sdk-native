# Root Herald — Native SDK

Embeddable static library for hardware-rooted device attestation. You link it
into your native app and call `Verify` to get back a verdict tied to the
device's TPM (Windows) or Secure Enclave (macOS). One C ABI, declared in
[`common/rootherald.h`](./common/rootherald.h); all platforms expose it, but
not all platforms have a working `Verify` yet — see the status column.

## Platforms

| Platform | Language | Hardware path | Artifact | Status |
|---|---|---|---|---|
| Windows | C++20 | NCrypt PCP + raw TBS | `RootHerald.lib` | Working (dogfooded on this developer's hardware against the real TPM; not yet third-party-validated) |
| Linux | C11 | tpm2-tss ESAPI | `librootherald.a` | **In development — one-call `Verify` NOT functional** (TPM evidence collection exists; the server-driven session flow that `Verify` needs is not wired up) |
| macOS | Obj-C | Secure Enclave | `librootherald.a` | **In development — one-call `Verify` NOT functional** (Secure Enclave key attestation is not yet server-verified) |
| Android | Kotlin | Hardware Key Attestation | AAR | Deferred |
| iOS | Swift | App Attest | Swift Package | Deferred |

> **What works today.** Only the **Windows** `Verify` performs a real,
> server-authoritative attestation (and only as developer-dogfooded — it has
> not been validated by an external integrator). On **Linux** and **macOS**,
> non-mock `RootHeraldClient_Verify` returns `ROOTHERALD_ERR_INTERNAL` with a
> "not yet implemented" reason rather than a verdict: the one-call flow is not
> wired to the real server protocol (which needs a server-created session and
> server-issued nonce). The mock path (`RootHeraldClient_SetMockTpm`) returns a
> canned `ALLOW` for CI only — it is not a real verdict and must never be used
> in production.

## Layout

```
common/    Public C ABI (rootherald.h, protocol.h) — the entire customer surface
windows/   C++   → RootHerald.lib
linux/     C     → librootherald.a
macos/     Obj-C → librootherald.a
samples/   minimal/ (hello-world per platform) + unity/ + unreal/
```

## Build

### Windows

```powershell
cmake -B build -S windows -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release --target RootHerald
# → build/Release/RootHerald.lib
```

### Linux

```bash
sudo apt install libtss2-dev libcurl4-openssl-dev cmake
cmake -B build -S linux
cmake --build build
# → build/librootherald.a
```

### macOS

```bash
cmake -B build -S macos
cmake --build build
# → build/librootherald.a
```

For CI/build agents without TPM hardware, Linux and macOS accept
`-DROOTHERALD_STUB=ON`, which returns canned evidence. Never ship a stub build.

## Use

The SDK links into your binary; there is no runtime DLL/SO/dylib dependency on
us and no daemon to install. Include the one public header and call `Verify`:

```c
#include <rootherald.h>

RootHeraldClient* c = RootHeraldClient_Create("rh_pk_live_...", NULL);
RootHeraldVerifyResult r;
if (RootHeraldClient_Verify(c, "game-launch", &r) == ROOTHERALD_OK) {
    /* r.verdict (ALLOW/WARN/DENY), r.device_id, r.tpm_class, r.reason */
}
RootHeraldClient_Destroy(c);
```

This works on **Windows** today. On **Linux** and **macOS** the same call
currently returns `ROOTHERALD_ERR_INTERNAL` ("not yet implemented") unless you
opt into mock mode — see the platform status table above before integrating.

Runnable copies live under [`samples/minimal/`](./samples/). For linking,
ABI/threading/memory contracts, and per-platform notes, see
[INTEGRATING.md](./INTEGRATING.md).

## Higher-level bindings

If you're not writing C/C++/Obj-C, use the language SDK instead — each wraps
this same library:

| Language | Package |
|---|---|
| C# / .NET | [`RootHerald.Native`](https://github.com/RootHerald/sdk-dotnet) (NuGet, P/Invoke) |
| React Native | [`@rootherald/react-native`](https://github.com/RootHerald/sdk-js) |

## License

MIT. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
