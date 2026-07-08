# Target client ABI (design direction)

> **Status: DONE (ABI 3.0).** This note merges two lineages (see *Provenance*). The
> **single-elevation / PCP-removal simplification** (ABI 2.0, 2026-06-27) and the
> **no-keys-in-client + backend-relayed enroll + remove `Verify`/`AttestSession`**
> direction (2026-06-30 design pass) have BOTH landed. The client is now keyless:
> it holds no RootHerald key of any kind and opens no socket to RootHerald — not
> the secret key, and no client-facing tenant key either (that whole concept and
> its request-header transport were removed entirely, not relocated). It was a
> breaking ABI change, accepted under the private/alpha tag. This note is retained
> for provenance/design rationale.

## Provenance (so we don't relitigate)

- **Single-elevation enroll + drop PCP (2026-06-27, in the working tree).** A great
  simplification of the client: enrollment collapsed to **one elevated raw-TBS
  ceremony** via `RootHeraldClient_Enroll`, and the **PCP / SHA-1-AIK key provider was
  deleted** (`pcp_key_provider.h` removed). PCP's only value was dodging the UAC prompt;
  once raw-TBS credential activation was proven under a single elevation, the dual-path
  complexity was dead weight. This also removed ABI 1.4's keyless page-relayed enroll
  split (`EnrollCollect`/`EnrollActivate`). **Keep all of this.**
- **No-keys / remove-`Verify` (2026-06-30, this design pass).** A verdict the client
  receives can be forged by whoever controls the client, so a verdict is only a
  security control when **enforced server-side** — which needs `rh_sk_`, which needs a
  customer backend. From that: the client should hold **no** RootHerald key, enroll +
  attest should be **backend-relayed**, and `Verify`/`AttestSession` (client-gets-verdict)
  should go. **This overrides only the *network/keys* and *Verify* choices of the
  06-27 work — not its elevation/PCP cleanup.**

The two are orthogonal: "single elevated raw-TBS ceremony" is a *TPM/UAC* decision;
"keyless / backend-relayed" is a *network* decision. We keep the former and add the
latter.

## The invariant that drives everything

**The client never holds a RootHerald API key, and never opens a socket to
RootHerald.** Not the secret key (`rh_sk_` — that can *never* be in a client), and
there is no client-facing key of any kind — the old client-facing tenant-key idea was
dropped, not relocated. The client's entire job is: **do local TPM
operations and hand opaque blobs to the embedder.** The embedder's backend moves those
blobs to/from RootHerald. (Enrollment still requires a one-time **elevation** for the
TPM work — that's a privilege concern, separate from holding a network key.)

## Current state vs. target delta

| Pillar | Current (ABI 2.0 working tree) | Target delta |
|---|---|---|
| **PreCheck** | `CollectPosture` (local readiness) — exists | Fold `GetDeviceInfo` in; rename to PreCheck |
| **Attest** | `CollectEvidence` — keyless, networkless, exists | Rename to Attest; otherwise done |
| **Enroll (TPM/UAC)** | Single elevated raw-TBS ceremony; PCP deleted — **done** | Keep as-is |
| **Enroll (network)** | `Enroll` POSTs **direct** to RootHerald (key-bearing) | **Make the two server legs backend-relayed (keyless)** — re-introduce 1.4's relay property on the TBS base, no PCP |
| **Verify / AttestSession / SetLinkToken** | Present (badge/Passport tier) | **Remove** |
| **Client key + `SetEndpoint`** | Present | **Remove** (client opens no RootHerald socket) |

So the bulk (PreCheck, keyless Attest, single-elevation/PCP-removed Enroll) is **already
in the tree**; the delta is: keyless-relay the enroll network legs, remove the
client-verdict surface, and tidy the naming.

## The three client verbs

| Verb | What it does | Network / keys | Returns |
|---|---|---|---|
| **Enroll** | One-time (or rotation) device-key bootstrap under a **single elevation**: gen AK, prove EK→AK via raw-TBS credential activation, register the device. | Local TPM ops under one elevation; the two server legs are **relayed by the embedder's backend**. No RootHerald socket, no key in client. | Enroll request/activation blobs (2-leg handshake — see below) + `deviceId`. |
| **Attest** | Per-attestation: fresh TPM quote over a **backend-issued nonce** → self-contained evidence blob. (Today's `CollectEvidence`.) | Local TPM op only. No socket, no key. | Evidence blob the backend submits to `/verify`. |
| **PreCheck** | Local readiness snapshot: TPM reachable? enrolled? Secure Boot on? OEM-keyed? — so a customer avoids spending an attestation that will hard-fail. (Today's `CollectPosture` + `GetDeviceInfo`.) | Local only. | Readiness **signals — never a verdict.** |

"Networkless / keyless" = the SDK call opens no connection to RootHerald and uses no
RootHerald key. Bytes still move (nonce in, blob out) over the **customer's own
client↔backend channel**, which the embedder owns; the SDK doesn't open it.

### Enroll: single elevation, but keyless-relayed

Credential activation is inherently interactive — the client presents EK + AK,
RootHerald encrypts a challenge **to that EK** (`TPM2_MakeCredential`), the client
decrypts it in the TPM (`TPM2_ActivateCredential`). The 06-27 work runs both TPM halves
under **one elevation** via raw-TBS (no PCP). The target keeps that and changes only
*who POSTs*: instead of `Enroll` POSTing to RootHerald itself, it **emits the `/enroll`
and `/activate` request bodies as blobs the customer backend relays** — i.e. a
`begin → complete` shape (`EnrollBegin() → enrollRequestBlob`; backend relays to
`/enroll`, returns the MakeCredential challenge; `EnrollComplete(challengeBlob) →
activationResponseBlob`; backend relays to `/activate`; `deviceId` known after leg 1).
This is exactly the relay property ABI 1.4 had — now on the simpler TBS/single-elevation
base, not the deleted PCP split.

**Open implementation detail:** the handshake interleaves a network round-trip between
the two TPM halves, so "single elevation" must span begin→complete (persist the elevated
worker across the relay, or re-enter the elevated context for the activate half). Settle
in implementation.

## The backend contract (server SDK side)

The "minimal backend infra" is concretely **one route handler** making these RootHerald
calls (all `rh_sk_`-authenticated):

1. **enroll-relay** — proxy the two enroll legs (`/devices/enroll`, `/devices/activate`).
2. **`POST /challenge`** — get a fresh nonce, hand it to the client (freshness / anti-replay).
3. **`POST /verify`** — submit the evidence blob, get the verdict, **enforce it
   server-side** (session state, short-lived session/EAT JWT, etc.).

The verdict is computed by RootHerald and returned **to the customer's backend** — it
never travels through the client.

## What is removed, and why

| Removed | Why |
|---|---|
| `RootHeraldClient_Verify` (client-gets-verdict) | A footgun: invites `if (verdict != allow) reject()` in client code, which *looks* like security but is trivially bypassed. Its only honest niche (non-adversarial / no-backend "badge") we are not pursuing. |
| `RootHeraldClient_AttestSession` + `SetLinkToken` | OIDC/authorization-code shape; only earns its keep for an IdP product (deferred — Shield-only). `Attest` does the same job with the client never touching RootHerald. Account binding = backend maps verified `deviceId` → its user. |
| `RootHeraldClient_GetDeviceInfo` | Folded into **PreCheck**. |
| Client key + `SetEndpoint` | Unnecessary once enroll is relayed and attest is keyless — the client holds no key and talks only to its own backend. |

Kept as mechanics (not "capabilities"): handle lifecycle (`Create`/`Destroy`), the
elevated-enroll entry (`RunElevatedEstablishKey` or its successor), logging, and gated
mock mode for CI.

## Things that are compositions, not new verbs

- **Step-up / re-attest (RFC 9470)** → call **Attest** again with a fresh nonce.
- **Key rotation** → **Enroll** with the re-enroll flag.
- **Device-bound accounts** → backend maps verified `deviceId` (UEID) → its user.
- **App / action scoping** → a *parameter* on Attest, not a verb.

## Privacy trade — and the future deniability layer

Backend-relayed enroll routes the **raw EK certificate** (a stable hardware identifier)
through the customer's backend in transit; today it's **plaintext PEM**
(`rootherald_win.cpp`, `DeviceController.cs`), so a relay can read it. Direct-to-RootHerald
enroll kept the EK away from the customer entirely. **v1 accepts this trade (EK
plaintext).**

**Future, opt-in deniability layer (deferred):** the customer's backend requests an
ephemeral keypair from RootHerald → hands the pubkey to the client → the client
**encrypts the EK cert to it** → the backend relays an **opaque** blob → only RootHerald
can decrypt the EK. Structural deniability ("we literally cannot identify the device's
hardware") for customers who need it. Confirmed a **small additive tweak** (~100 LOC):
add `ekCertEncrypted` + `ekCertKeyId`, decrypt **before** EK-chain validation (point
unchanged at `EkCertificateValidator.cs:160`); no change to the TPM/MakeCredential/
ActivateCredential flow.

## Open items

- **Single-elevation across begin→complete** — the enroll handshake interleaves a
  network round-trip between the two TPM halves; decide how the elevation spans it.
- **Migration** — breaking ABI bump; sequence with the server SDKs' relay/challenge/
  verify helpers and the e2e `/try` gate. See `docs/abi-migration-plan.md`.
- **EK-opacity / deniability** — resolved as feasible (above); deferred to post-v1.
