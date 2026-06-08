# Root Herald — Native SDK

Embeddable static library for hardware-rooted device attestation. You link it
into your native app, call `Verify`, and get back a signed verdict tied to the
device's TPM (Windows/Linux) or Secure Enclave (macOS). One C ABI, declared in
[`common/rootherald.h`](./common/rootherald.h); all platforms implement it.

## Platforms

| Platform | Language | Hardware path | Artifact | Status |
|---|---|---|---|---|
| Windows | C++20 | NCrypt PCP + raw TBS | `RootHerald.lib` | GA |
| Linux | C11 | tpm2-tss ESAPI | `librootherald.a` | Beta |
| macOS | Obj-C | Secure Enclave | `librootherald.a` | Beta |
| Android | Kotlin | Hardware Key Attestation | AAR | Deferred |
| iOS | Swift | App Attest | Swift Package | Deferred |

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
