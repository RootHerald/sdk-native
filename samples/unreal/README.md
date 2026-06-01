# RootHerald Unreal Engine Sample Plugin

A minimal Unreal Engine 5 plugin (`RootHeraldUE`) that dynamically loads
`RootHerald.dll` and exposes a Blueprint-callable `Verify(Action)` function.

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
5. Add the *Verify Device* Blueprint node to your game-launch Blueprint
   (see `Content/Sample/BP_LauncherGate.uasset` once you import the sample
   content from `SampleContent/`).

## C++ usage

```cpp
#include "RootHeraldClient.h"

void AMyGameMode::OnPlayerJoined(APlayerController* PC)
{
    URootHeraldClient* Client = NewObject<URootHeraldClient>();
    Client->Initialize(TEXT("rh_pk_live_REPLACE_ME"), TEXT("https://rootherald.io"));
    FRootHeraldVerifyResult R = Client->Verify(TEXT("match-join"));
    if (R.Verdict != ERootHeraldVerdict::Allow)
    {
        UE_LOG(LogGame, Warning, TEXT("RH denied: %s"), *R.Reason);
        PC->ClientWasKicked(FText::FromString(TEXT("Device verification failed.")));
    }
}
```

## Blueprint usage

The sample Blueprint `BP_LauncherGate` wires:

1. `Event BeginPlay` →
2. `Initialize Root Herald Client` (publishable key, endpoint URL) →
3. `Verify Device` (action = "game-launch") →
4. `Branch` on the verdict → `Open Level` (main menu) / `Show Error`.

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
