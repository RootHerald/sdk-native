# RootHerald Unity Sample

A minimal Unity 2022 LTS+ project that demonstrates how to drop the Root
Herald native SDK into a Unity title and gate a sign-up button on the
attestation verdict.

## Drop-in steps

1. Copy the `Assets/RootHerald/` folder from this sample into your own
   project's `Assets/`.
2. Drop the platform-specific native libraries into `Assets/RootHerald/Plugins/`:
   - **Windows standalone** — `RootHerald.dll` (x64) under
     `Assets/RootHerald/Plugins/Windows/x86_64/`.
   - **macOS standalone** — `RootHeraldKit.framework` under
     `Assets/RootHerald/Plugins/macOS/`.
   - **Android** — drop the AAR (`rootherald-release.aar`) under
     `Assets/RootHerald/Plugins/Android/`.
   - **iOS** — Unity will pick up the XCFramework from the iOS Resolver
     when you place `RootHeraldKit.xcframework` under
     `Assets/RootHerald/Plugins/iOS/`.
3. Install the NuGet `RootHerald.Native` package (the .NET wrapper)
   into Unity. The recommended path is via the
   [NuGetForUnity](https://github.com/GlitchEnzo/NuGetForUnity) plugin so
   the managed wrapper's transitive references are resolved automatically.
4. No RootHerald key goes in the client — the SDK is keyless. The
   `RootHeraldGate` script collects attestation evidence locally and hands it
   to YOUR backend, which relays it to RootHerald with your `rh_sk_` secret and
   enforces the verdict server-side (see
   `Assets/RootHerald/Scripts/RootHeraldGate.cs`).
5. Open `Assets/RootHerald/Scenes/Sample.unity` and press Play.

## Scene contents

`Sample.unity` is a one-canvas scene with:

- A `Button` labelled *Verify device*
- A `Text` element bound to the gate's status string
- A GameObject with the `RootHeraldGate` component attached, listening to
  the button's `OnClick` event

## Why not vendor the library directly?

Anti-cheat and licensing rules vary per studio. Shipping the native binary
inside the sample would bind every consumer to a specific Root Herald
release; instead, this template tells you exactly where to drop the binary
you fetched from the release page or from the NuGet package.

## Caveats

- Editor mode runs the .NET managed shell that loads `RootHerald.dll`. The
  TPM call works on Windows and macOS dev machines that have the native
  library installed; the editor will print a clear error when the library
  isn't found.
- WebGL builds cannot call the native SDK; for browser builds, use the
  Root Herald browser extension fallback in your matchmaker.
