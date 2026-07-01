# ABI migration plan — align the product surface to the target client ABI

Companion to `target-abi.md`. This is the work-package decomposition for migrating
the **entire** product to: client SDKs expose only **Enroll / Attest / PreCheck**
with **zero RootHerald keys in the client** and **backend-mediated** enroll+attest;
server SDKs expose **enroll-relay / challenge / verify**; `Verify` / `AttestSession`
/ `SetLinkToken` removed. Integration gate: **real e2e `/try` on hardware.**

## The core change (why this is big)

Today the **client** opens the HTTP sockets to RootHerald and holds the site key
(`rootherald_win.cpp` does `HttpPost` for enroll/activate; `@rootherald/browser`/the
host POST directly). The target moves **all RootHerald network I/O out of the client**:
the client only does local TPM ops and emits/consumes **opaque blobs**; the
**customer's backend** (server SDK, `rh_sk_`) relays those blobs to RootHerald. That
transport-removal is the spine of the migration and the riskiest part.

## Interface contract (the foundation everything builds against)

**Client verbs (language-neutral):**
- `PreCheck() -> PostureSignals` — local only; signals, never a verdict.
- `EnrollBegin() -> EnrollRequestBlob` — local: gen AK, gather EK pub/cert + AK pub.
- `EnrollComplete(ActivationChallengeBlob) -> ActivationResponseBlob (+ deviceId)` —
  local: `TPM2_ActivateCredential`.
- `Attest(nonce) -> EvidenceBlob` — local: TPM quote over the backend-issued nonce.

**Backend HTTP contract (server SDK helpers, all `rh_sk_`-authenticated):**
- `relayEnroll(EnrollRequestBlob) -> ActivationChallengeBlob`  → `POST /api/v1/devices/enroll`
- `relayActivate(ActivationResponseBlob) -> { deviceId }`       → `POST /api/v1/devices/activate`
- `issueChallenge() -> { nonce }`                               → `POST /api/v1/.../challenge`
- `verify(EvidenceBlob, policy?) -> Verdict`                    → `POST /api/v1/attestations/verify`

**Blob shapes** = today's JSON payloads (EnrollmentRequest; credentialBlob+encryptedSecret;
{deviceId,decryptedSecret}; AttestationRequest-shaped evidence; Verdict). Canonicalized
in `@rootherald/contracts` (TS source of truth) and mirrored per language. EK cert stays
**plaintext for v1** (deniability layer deferred — see target-abi.md).

**Removed everywhere:** `Verify` (client-gets-verdict), `AttestSession` + `SetLinkToken`,
client publishable key + `SetEndpoint`.

## Work packages

| # | Package | Repo | Depends on | Scope | Build/test here? |
|---|---|---|---|---|---|
| WP0 | **Interface contract** — protocol spec + `@rootherald/contracts` types (3 verbs, 4 blobs, backend HTTP contract, error model). Single source of truth. | sdk-js (contracts) | — | M | ✅ |
| WP1 | **platform/services/api** — confirm enroll/activate/challenge/verify support backend relay with `rh_sk_` server auth; deprecate client/site-key verdict endpoints (Verify/AttestSession server side); EK plaintext kept. | platform | WP0 | M | ✅ (xUnit) |
| WP2 | **sdk-native** — refactor C ABI to Enroll(begin/complete)/Attest/PreCheck emitting/consuming blobs; **remove in-SDK HTTP transport + site key + SetEndpoint + Verify/AttestSession/SetLinkToken**. Windows real; Linux/macOS honesty-guarded. RISKIEST — front-load. | sdk-native | WP0 | L | ⚠️ C++/VS2022 |
| WP3 | **sdk-js** — `@rootherald/browser` (3-verb blob client, no RootHerald I/O), `@rootherald/node` (relay/challenge/verify server helpers). | sdk-js | WP0 | L | ✅ |
| WP4a–e | **server SDKs** — go / php / ruby / java / dotnet: implement relay/challenge/verify; remove client-verdict helpers. Parallel, independent. | sdk-go/php/ruby/java/dotnet | WP0 | M ea | ⚠️ per toolchain |
| WP5 | **browser-extension** — page↔host message protocol → new blob relay (enroll begin/complete, attest collect); drop verdict handling. | browser-extension | WP0, WP6 | M | ✅ |
| WP6 | **windows-host** — native-messaging-host actions → new sdk-native API; host emits blobs for relay, no longer POSTs to RootHerald for a verdict. | windows-host | WP2 | M | ⚠️ C++/VS2022 |
| WP7 | **fake-customer-web /try** (INTEGRATION + GATE) — frontend uses `@rootherald/browser` via extension→host; `lib/try-proxy.ts` (the "customer backend") uses `@rootherald/node` relay/challenge/verify with `rh_sk_`. Real e2e on hardware. | platform | WP1,2,3,5,6 | L | ✅ + hardware |

## Execution order (fan-out)

```
WP0 (contract)
  ├─ WP1 (api)            ┐
  ├─ WP2 (sdk-native) ★   │  parallel after WP0
  ├─ WP3 (sdk-js)         │  (different repos, contract fixed)
  └─ WP4a–e (server SDKs) ┘
        WP2 → WP6 (windows-host) → WP5 (extension)
                                      └─→ WP7 (/try integration + e2e GATE)
```
★ front-loaded risk. CI/tests are the gate per package; nothing integrates red.

## Risks / unknowns

- **R1 — native build for the real e2e (the big one).** WP2 + WP6 are C++/Obj-C; the
  real `/try` gate needs `sdk-native` + `windows-host` **recompiled and the host
  reinstalled on this Windows machine** (VS2022 + cmake). The agent environment may not
  compile C++ — if not, the user builds/reinstalls. This gates "tests passing on real
  e2e." **Decide the native-build approach before WP2 lands.**
- **R2 — breaking ABI across published (alpha) SDKs.** Acceptable under the alpha tag;
  coordinate version bumps; land client+server halves together.
- **R3 — server-SDK toolchains** (go/php/ruby/java/dotnet) may be absent in the agent
  env → their tests run in CI, not here. Build best-effort; CI is the gate.
- **R4 — transport removal in sdk-native** is a deep refactor (HTTP → blob emit). Front-
  load, characterize current behavior first, keep Linux/macOS honesty-guarded.
- **R5 — e2e needs reseed/re-enroll** on the local stack after the ABI change (existing
  `/try` re-enroll fallback applies).

## Reality: this is a DELTA, not greenfield

Much of the target is already in the working tree (ABI 2.0, 2026-06-27): PreCheck
(`CollectPosture`), keyless Attest (`CollectEvidence`), and single-elevation enroll with
PCP removed. See `target-abi.md` → *Current state vs. target delta*. The packages below
are scoped to the **remaining delta** on top of that, not a from-scratch build.

## Verification strategy (per package)
- **TS/JS (contract, sdk-js, extension, fake-customer-web)** — build + vitest **locally**.
- **.NET API** — build + xUnit **locally**.
- **C++ natives (sdk-native, windows-host)** — source edits locally; **CI builds** on
  push (no local cmake). The real host installer comes from `windows-host` `release.yml`
  (rolling `alpha` pre-release) and is pulled locally by `dev-up.ps1`.
- **Other server SDKs (go/php/ruby/java)** — source edits; **their CI** is the gate.
- **e2e `/try`** — `dev-up.ps1` pulls the CI-built alpha host → docker stack → real
  hardware run. Requires pushing `windows-host` to cut the release (flagged outward step).

## Status (branch `feat/client-abi-2.0` in every repo)
- **Baseline committed** (2026-06-30): sdk-native `acd3e91`, sdk-js `b017863`,
  browser-extension `f90f328`, windows-host `75b0480`, platform `531e968`.
- EK-opacity gate: **resolved** (plaintext v1; deniability = deferred additive tweak).
- **WP0 contract** ✅ (409 union canonicalized). **WP1 API** ✅ (630 tests; activate now
  accepts rh_sk_; client-verdict endpoints flagged deprecated). **WP2 sdk-native** ✅
  (ABI 3.0; keyless Create; EnrollBegin/EnrollComplete; Verify/AttestSession/SetLinkToken
  removed; **compiled locally on VS2022 + ran vs real TPM**; Linux/macOS CI-gated).
  **WP3a node** ✅ (57 tests). **WP3b browser** ✅ (32 tests). **WP4 server SDKs** ✅
  (dotnet 23 / go container-verified / ruby container-verified / java + php
  correct-by-construction, CI-gated). **WP5 extension** ✅ (chrome/edge/firefox build).
  **WP6 windows-host** ✅ (host+tray+installer built locally; resident elevated worker via
  named-pipe IPC spans EnrollBegin→Complete). **WP7 /try** ✅ (rewired + re-vendored;
  116 vitest; docker builds; stack up; /try 200).
- **All changes uncommitted** on `feat/client-abi-2.0` (working trees).
- **Remaining: real-hardware e2e** — install the new host + load the new extension +
  click-through with UAC on the real TPM (human-in-the-loop).

## Residual follow-ups (flagged, not blocking)
- `@rootherald/node` `verify` drops top-level `assuranceClaimsMet` (contract
  `VerifyAttestationResponse` only models `{verdict, token}`); the /try BFF kept the raw
  `brokerVerify` for that leg. To make the node `verify` helper complete, add
  `assuranceClaimsMet` to the contract + all server SDKs' `verify`.
- `vendor/` is gitignored — the new `vendor/rootherald-sdk/contracts/dist/{server,enroll}.*`
  must be `git add -f`'d before commit/CI or a fresh checkout misses the `/server` subpath.
- sdk-dotnet's deferred `RootHerald.Native` FFI *preview* still exposes client-side
  `Verify`/`SetEndpoint` — needs its own ABI-3.0 pass (deferred package).
- windows-host `ci.yml` `SDK_NATIVE_REF` points at the branch; repin to a committed
  sdk-native SHA once WP2 lands.
