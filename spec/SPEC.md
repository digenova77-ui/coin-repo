# COIN SYSTEM SPEC (public layer)

Grown from the v0 pointer, section by section, each section carrying its
source pointer into the ratified corpus and its honest grade. Rule carried
from the pointer itself: *nothing is specified here ahead of its source —
an unwritten section is an honest gap, not an invitation to improvise one.*

Grades: PROVEN (receipt in hand) · REPORTED (a named source says so) ·
INFERRED (derived, shown) · DESIGN (specified, unbuilt) · UNKNOWN (named,
not filled).

---

## 1. What this is

A deterministic coin system: a hash-chained public ledger, a deterministic
kernel in which agreement comes from re-execution rather than from a
validator council, a wallet face, and a quantifiable anchor (Ground
Control, §6) at the base of the unit. The coin is never bought or sold.
Nothing in this spec is an issuance, a mint, a listing, or a mainnet act.

- Source: `README.md` (this repo); `~/workspace/coin-live/DESIGN.md` §1.
- Grade: the repository and its genesis entry EXIST (PROVEN, commit
  `94a93351`); the system they specify is DESIGN except where a section
  says otherwise.

## 2. Layers

Three layers, kept distinct, mechanically:

- **CODE + RULES (public)** — this spec, `rules/`. Rule changes land here
  first, in the open, with a receipt, before any mechanism moves.
- **LEDGER (public, mirrored)** — the white ledger: append-only public
  records of proof. The dark ledger (private, operational) is never
  mirrored anywhere.
- **KEYS (never here)** — no private keys, seeds, or signing material in
  any repository. Enforcement is mechanical: `tools/guard.sh` refuses
  key-shaped material at commit time.

- Source: `README.md`; `ledger/GENESIS.md`.
- Grade: PROVEN (the split is on disk and the guard has refused test
  commits).

## 3. The white ledger

- Entries are append-only. Corrections are new entries, never edits.
- Every entry names the hash of the entry before it; the chain is the
  receipt. An entry's hash is the SHA-256 of its file bytes; the head
  hash is the hash of the latest entry.
- Entry 0 is genesis (2026-10-12): the ledger records the public layer
  only; no issuance has happened; the ledger beyond genesis is empty of
  units — and that emptiness is published, verifiable fact, not a promise.
- A signed head manifest (`ledger/head-manifest.json`) attests the
  current head: head hash, height, and the genesis hash, signed under
  the house Ed25519 regime. The signing key is TRANSITIONAL (generated
  on-lane, pending the owner-device ceremony); every record it touches
  is marked LEGACY and will be re-sealed when the ceremony key arms.

- Source: `ledger/GENESIS.md`; `~/workspace/swarm-node/signing/`
  (the house Ed25519 regime); binding law in
  `~/workspace/goals/idea-tracking/files/61-unity-asset-binding.md`.
- Grade: PROVEN (chain + manifest exist and verify); key status
  TRANSITIONAL/LEGACY by standing law.

## 4. The kernel

The ledger is the state; transactions are state transitions; every node
that starts from the same state and applies the same signed inputs
arrives at the same new state. **Determinism is the consensus** — there
is no validator set, no Unique Node List, nothing to capture.

- The transition function is pure: `apply(state, tx) → new_state | reject`.
  No wall-clock reads, no randomness, no host fingerprints inside the
  function; anything non-deterministic enters only as signed input data.
- Each transition carries `tx_id` (hash of its canonical bytes),
  `invariant_hash` (hash of the invariants it must preserve — if the
  invariants break, the transition dies), and `signature` (verified
  against the signer's Unity ID grant).

- Source: `~/workspace/goals/idea-tracking/files/15-coin-vm-architecture.md`
  §1 (the V2 manifest sketch is REAL; the specification is DESIGN).
- Grade: **W1 BUILT** (Oct 12, 2026) — the deterministic kernel exists
  as running code in `kernel/` of this repo: append/verify over the
  hash-chained ledger, state derived only by folding, the dual-pipe
  verifier as its verify path, a Joule-meter seam (MODELED only, W6
  unbuilt), no network I/O, and issuance refused by construction with
  tests proving the refusal. It changes nothing in §9: the battery
  has not been executed against it and the verdict there stands
  until it is. Transaction-level grant signatures (W2) are not built.

## 5. Identity — Unity ID binding

A Unity ID binds to real-world assets and to the coin through a six-step
ceremony (submit → grade → verify → collapse → write-white →
write-dark), implemented as running code:

- The **white ledger** holds proof of a binding only — no private
  identifiers; a concealment scan refuses any white record carrying one.
- The **dark ledger** holds the sealed private record and, by itself,
  can transfer nothing: the ability to transfer lives in the owner's
  live key, never in a record.
- Mutual validation: receipts bind coin to ID; lanes cross-validate;
  *no receipt, no coins.*

- Source: `~/workspace/goals/idea-tracking/files/61-unity-asset-binding.md`;
  implementation `~/workspace/unity-bindings/tools/bind.py` (case zero
  bound and verified, Oct 12, 2026).
- Grade: PROVEN as a ceremony for bindings (one live case);
  TRANSITIONAL/LEGACY key status as in §3.

## 6. Ground Control — the anchor

The reserve is **Ground Control, not escrow** (David, Oct 12, 2026,
sealed): the quantifiable anchor at the base root of the unit — the fuel
peg — against which the unit is defined and spending is metered.

- **Escrow** = a third party holds your funds against conditions it
  judges. Custody plus discretion. Ground Control is neither: nobody
  holds anybody's funds.
- The base quantity is measured compute — the Joule — metered by the
  VM's Joule meter daemon. Until a real meter exists, every metering
  figure shown anywhere in this system is labeled DEMO or MODELED.
- `peg_ratio_E` — the ratio between the unit and its ground — is
  **UNDECIDED**. It is David's number, pen-alone. No live emission of
  any kind occurs before it is decided, and this spec does not
  pre-decide a digit of it.

- Source: `~/workspace/coin-live/DESIGN.md` §5; `ledger/GROUND-CONTROL.md`
  (white ledger entry 1, the published doctrine statement);
  `15-coin-vm-architecture.md` §4 (Joule meter daemon).
- Grade: doctrine PROVEN as published; the meter is DESIGN; the ratio
  is UNKNOWN (open by decision, not by oversight).

## 7. The one-file world and the pings

The coin is a world in one file: a userspace process that boots on any
host (native binary per platform; a WASM/browser build is the demo
path), draws its membrane, takes exactly the grants it needs — each
named, each deniable — and runs its daemons: heartbeat, ledger sync,
witness listener, Joule meter, pin daemon.

The coin **initiates every contact** with the outside; no server can
call it, wake it, or hold a standing connection to it. Its pings fetch
public, hash-named things only — a signed ledger-head manifest, chain
segments, media plates by content hash, storage reads, pin deliveries —
and every fetch is verified locally against its hash before use.
Offline, the coin loses freshness and nothing else: it boots, verifies
its entire local chain (verification is local math), and labels the age
of its last verified head honestly. Endpoints are a signed, hash-chained
registry (`endpoints.json`) — replaceable data, never hard-coded trust.

- Source: `15-coin-vm-architecture.md` §§2–4;
  `~/workspace/coin-live/DESIGN.md` §2.
- Grade: **W8 BUILT in its single-file form** (Oct 12, 2026) —
  `coin.py` at this repo's root: one self-contained file carrying the
  verifier, the kernel fold, and the published chain; run it and it
  verifies the chain locally and performs the P1 head check against
  the signed registry's endpoints. The per-platform packaging of
  §7's table (native binaries, the WASM/browser demo path) and the
  remaining pings (P2–P5, build items W4/W5) remain DESIGN. The
  Tier 0 channels the pings ride today (GitHub mirror, IPFS) EXIST.

## 8. Issuance — the fence

**No issuance happens in or from this repository.** Issuance, the
identity keypair ceremony, T3, and any mainnet approval are pen-alone
items behind named gates: the ratified security battery sealed against
a real implementation, and `peg_ratio_E` decided. The full rules layer
lives in `rules/ISSUANCE.md`, verbatim, and changes land there first.

- Source: `rules/ISSUANCE.md`.
- Grade: PROVEN as standing law (nothing has been issued; the published
  ledger is the evidence).

## 9. The security standard and the readiness verdict

"Ready" is defined by the ratified battery `ED-PREDICT-20261004-EFUSETST-V1`:
Layers A–E executed against a **real implementation**, every test green,
three clean full runs, an independent adversarial re-run, and a Trinity
PASS on the evidence → seal.

The standing verdict (Oct 4, 2026 audit) is **NOT READY**: the standard
is ratified law and the battery is specified, but no coin implementation
exists, so the battery has no subject. *"Never: testing a mock and
calling it the coin. A mock proves the harness; only the real
implementation proves the coin."* This verdict is published here
because a launch document that hides its own NOT READY is marketing;
this one is a spec.

- Source: `~/workspace/COIN_AUDIT_20261004.md` §2;
  `EFUSE_SECURITY_TEST_DESIGN.md` (battery specification).
- Grade: PROVEN (the verdict and its checklist are on record).

## 10. Liveness tiers

"Live" is three switches, not one:

- **Tier 0 (this publication):** the spec, the genesis ledger with its
  signed head, the Ground Control entry, the wallet demo labeled DEMO,
  the endpoint registry — all public, all verifiable, no value moved,
  no gate crossed.
- **Tier 1:** real media/storage endpoints on our own servers and the
  wallet fetching live heads — lands the day the sovereign mesh does.
- **Tier 2 (gated, unscheduled):** issuance and the value-bearing
  instrument, behind §8's fence and §9's seal. No date is announced for
  a gated tier; gates open on evidence, not calendars.

- Source: `~/workspace/coin-live/DESIGN.md` §§1, 6.
- Grade: Tier 0 PROVEN by the artifacts this spec ships with; Tiers 1–2
  DESIGN/gated as marked.

---

*Spec ends. Publication of this spec asserts nothing beyond its grades.
Where a section says DESIGN, it is a drawing of a thing to build — the
house rule stands: a definition proves itself only manifested in a
real-time runtime.*
