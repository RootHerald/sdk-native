# RootHerald Unreal Engine Sample Plugin

A minimal Unreal Engine 5 plugin (`RootHeraldUE`) that dynamically loads
`RootHerald.dll` and exposes a Blueprint-callable `CollectEvidence(NonceB64)`
function (ABI 3.0 — keyless). The client emits an evidence blob; your game
backend relays it to RootHerald and enforces the verdict server-side.

## Drop-in steps

1. Copy `Plugins/RootHeraldUE/` into your Unreal project's `Plugins/`
   directory.
2. Drop the platform-specific native libraries beside the plugin:
   - **Windows** — `RootHerald.dll` under
     `Plugins/RootHeraldUE/Binaries/Win64/`.
   - **macOS** — `RootHeraldKit.framework` under
     `Plugins/RootHeraldUE/Binaries/Mac/`.
   - **Linux server** — `librootherald.so` under
     `Plugins/RootHeraldUE/Binaries/Linux/`.
3. Regenerate your project files (right-click the `.uproject` →
   *Generate Visual Studio project files*).
4. Open the editor → *Edit → Plugins → Installed → RootHeraldUE → Enabled*.
5. Add the *Collect Evidence* Blueprint node to your game-launch Blueprint
   (see `Content/Sample/BP_LauncherGate.uasset` once you import the sample
   content from `SampleContent/`).

## C++ usage

```cpp
#include "RootHeraldClient.h"

void AMyGameMode::OnPlayerJoined(APlayerController* PC, const FString& NonceB64)
{
    // NonceB64 came from YOUR backend (POST /api/v1/.../challenge).
    URootHeraldClient* Client = NewObject<URootHeraldClient>();
    Client->Initialize();                                  // keyless: no key, no endpoint
    FString Evidence = Client->CollectEvidence(NonceB64);  // local quote over the nonce
    if (Evidence.IsEmpty())
    {
        UE_LOG(LogGame, Warning, TEXT("RH evidence collection failed"));
        return;
    }
    // Send Evidence to YOUR backend, which relays it to
    // POST /api/v1/attestations/verify (rh_sk_ auth) and enforces the verdict.
    SendEvidenceToBackend(PC, Evidence);
}
```

## Blueprint usage

The sample Blueprint `BP_LauncherGate` wires:

1. `Event BeginPlay` →
2. `Initialize Root Herald Client` (keyless — no args) →
3. `Collect Evidence` (nonce from your backend) →
4. Send the evidence blob to your backend, which relays it and enforces the
   verdict, then signals the client to `Open Level` / `Show Error`.

A screenshot of the assembled graph lives at
`SampleContent/Screenshots/BP_LauncherGate.png` (placeholder; capture from
your editor on first import).

## Caveats

- Hot reload doesn't always pick up `RootHerald.dll` changes — restart the
  editor after dropping a new binary.
- The plugin links the C ABI via `FPlatformProcess::GetDllHandle`; it does
  not statically link, so the DLL is optional in editor builds without
  breaking the build.
- iOS / Android shipping requires bundling the corresponding native artifact
  (XCFramework / AAR); the .Build.cs file demonstrates the conditional
  inclusion.
