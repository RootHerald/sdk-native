# Root Herald — Native SDK

Embeddable static library for hardware-rooted device attestation. You link it
into your native app and call `Verify` to get back a verdict tied to the
device's TPM (Windows) or Secure Enclave (macOS). One C ABI, declared in
[`common/rootherald.h`](./common/rootherald.h); all platforms expose it, but
not all platforms have a working `Verify` yet; see the status column.

## Platforms

| Platform | Language | Hardware path | Artifact | Status |
|---|---|---|---|---|
| Windows | C++20 | NCrypt PCP + raw TBS | `RootHerald.lib` | Working (dogfooded on this developer's hardware against the real TPM; not yet third-party-validated) |
| Linux | C11 | tpm2-tss ESAPI | `librootherald.a` | **In development — keyless verbs NOT functional** (return `ROOTHERALD_ERR_INTERNAL`; the tpm2-tss collectors are not wired up) |
| macOS | Obj-C | Secure Enclave | `librootherald.a` | **In development — keyless verbs NOT functional** (Secure Enclave collectors not wired up) |
| Android | Kotlin | Hardware Key Attestation | AAR | Deferred |
| iOS | Swift | App Attest | Swift Package | Deferred |

> **Keyless client (ABI 3.0).** The client holds no RootHerald key and opens no
> socket to RootHerald: it does local TPM work and emits opaque blobs your
> backend relays (`EnrollBegin`/`EnrollComplete` → `/devices/enroll`+`/activate`;
> `CollectEvidence` → `/attestations/verify`). The verdict is computed and
> enforced server-side and never travels through the client.
>
> **What works today.** Only the **Windows** keyless verbs perform real TPM work
> (and only as developer-dogfooded — not yet validated by an external
> integrator). On **Linux** and **macOS** they return `ROOTHERALD_ERR_INTERNAL`
> ("not yet implemented") until the per-platform collectors land.

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
us and no daemon to install. Include the one public header; the client is keyless
and hands you opaque blobs your backend relays to RootHerald:

```c
#include <rootherald.h>

RootHeraldClient* c = RootHeraldClient_Create();   /* no key, no endpoint */

/* Per-attestation: a fresh quote over a backend-issued nonce. */
char* evidence = NULL;
if (RootHeraldClient_CollectEvidence(nonce_b64, &evidence) == ROOTHERALD_OK) {
    send_to_my_backend(evidence);   /* backend relays to /attestations/verify */
    RootHeraldClient_FreeEvidence(evidence);
}
RootHeraldClient_Destroy(c);
```

Enrollment is the two-leg keyless handshake `RootHeraldClient_EnrollBegin` →
(backend relays) → `RootHeraldClient_EnrollComplete`; see
[INTEGRATING.md](./INTEGRATING.md). This works on **Windows** today. On **Linux**
and **macOS** these calls currently return `ROOTHERALD_ERR_INTERNAL` ("not yet
implemented"); see the platform status table above before integrating.

Runnable copies live under [`samples/minimal/`](./samples/). For linking,
ABI/threading/memory contracts, and per-platform notes, see
[INTEGRATING.md](./INTEGRATING.md).

## Higher-level bindings

If you're not writing C/C++/Obj-C, use the language SDK instead. Each wraps
this same library:

| Language | Package |
|---|---|
| C# / .NET | [`RootHerald.Native`](https://github.com/RootHerald/sdk-dotnet) (NuGet, P/Invoke) |
| React Native | [`@rootherald/react-native`](https://github.com/RootHerald/sdk-js) |

## License

MIT. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
