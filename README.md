# Root Herald — Native Client SDKs

Hardware-rooted device attestation for desktop and mobile platforms. Each platform's SDK talks directly to its native attestation primitives (Windows TPM, Linux TPM, macOS Secure Enclave, Android Keystore, iOS App Attest) and exposes a common C ABI so higher-level language bindings (.NET, Python, Rust, Node) wrap the same surface.

## Platform matrix

| Platform | Language | Hardware path | Status |
|---|---|---|---|
| Windows | C++ (C++20) | NCrypt PCP + raw TBS | **GA** — proven end-to-end against real Intel PTT / discrete TPMs |
| Linux | C (C11) | tpm2-tss ESAPI | **Beta** — code complete; hardware verification pending |
| macOS | Objective-C | Secure Enclave key attestation | **Beta** — code complete; hardware verification pending |
| Android | Kotlin | Hardware Key Attestation (TEE / StrongBox) | Pending (next wave) |
| iOS | Swift | DCAppAttestService (App Attest) | Pending (next wave) |

## Layout

```
.
├── common/         # Shared C headers — public ABI declared here
│   ├── rootherald.h         # The C ABI all platforms implement
│   └── protocol.h           # Wire-protocol structs
├── windows/        # C++ — RootHerald.lib (static archive)
├── linux/          # C   — librootherald.a (static archive)
├── macos/          # Obj-C — static framework
├── android/        # Kotlin — AAR (deferred)
├── ios/            # Swift — Swift Package (deferred)
└── samples/        # Unity, Unreal samples + minimal hello-world per platform
```

## What the SDK does

```c
RootHeraldClient* client;
RootHeraldClient_Create(&client, "https://api.rootherald.io", "your_app_id");
RootHeraldVerifyResult result;
RootHeraldClient_Verify(client, "action-name", &result);
// result.token       — JWT to send to your backend
// result.verdict     — PASS | WARN | FAIL
// result.deviceId    — stable identifier for this machine
RootHeraldClient_Destroy(client);
```

All implementations expose the **same** C ABI declared in `common/rootherald.h`. The verbosity above is the C surface; per-platform idiomatic wrappers (C++ `RootHeraldClient` class, Kotlin `class RootHeraldClient`, Swift `final class RootHeraldClient`) cover the same operations.

## Why these SDKs are open source

Hardware attestation is a trust product. There's no hidden crypto here — server-side validators do the heavy lifting (signed by the Root Herald JWKS the customer's backend verifies against). Open source lets you audit exactly what the SDK does on the end-user's device: no telemetry, no exfiltration, no backdoors. The whole point of attestation is provable trust; closed source would undermine that.

## Build

### Windows

```powershell
cmake -B build/windows -S windows -G "Visual Studio 17 2022" -A x64
cmake --build build/windows --config Release
# Produces: build/windows/Release/RootHerald.lib
```

### Linux

```bash
sudo apt install libtss2-dev libcurl4-openssl-dev cmake
cmake -B build/linux -S linux
cmake --build build/linux
# Produces: build/linux/librootherald.a
```

### macOS

```bash
cmake -B build/macos -S macos -G Xcode
cmake --build build/macos --config Release
```

### Android (deferred)

```bash
cd android && ./gradlew :rootherald:assembleRelease
```

### iOS (deferred)

Add as Swift Package dependency: `https://github.com/RootHerald/sdk-native` and select the `ios` product.

## Integration topology

This SDK is one of two paths a customer's app can use:

- **Topology B — Embedded:** Customer links our SDK statically into their native app. The SDK calls Root Herald API directly OR through the customer's reverse proxy (transport mode `proxy`).
- **Topology A — Browser:** Customer's web page uses `@rootherald/js`, which talks to the Root Herald browser extension, which talks to the platform-specific native messaging host shipped by Root Herald. The SDK in this repo is what the native host links against.

See the platform repo's docs for the full architecture.

## Trust chain

The SDK signs attestation evidence with platform-bound keys (TPM AK, Secure Enclave key, etc.) that can't be exported. Root Herald verifies the signature server-side against trust anchors rooted in the device manufacturer's PKI. Customers verify the resulting JWT against Root Herald's [JWKS](https://api.rootherald.io/.well-known/jwks.json).

See [docs/security-model.md](./docs/security-model.md) in this repo (when migrated) for the full chain.

## Higher-level language bindings

If you're not writing in C/C++/Obj-C/Kotlin/Swift, use the language-specific SDK instead:

| Your language | Use this | Notes |
|---|---|---|
| C# / .NET (Windows/Linux/macOS desktop) | [`RootHerald.Native`](https://github.com/RootHerald/sdk-dotnet) | NuGet, P/Invokes the C ABI |
| Python (desktop) | `rootherald-native` (deferred) | ctypes binding |
| Rust (desktop) | `rootherald` (deferred) | FFI binding |
| Electron / Node desktop | `@rootherald/native` (deferred) | N-API |
| React Native mobile | [`@rootherald/react-native`](https://github.com/RootHerald/sdk-js) | bridges to native Android/iOS |

## License

MIT. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
