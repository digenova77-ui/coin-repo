# KERNEL ISO — SPEC

**Version:** v0 · **Status: BETA** · **Cut:** Oct 12, 2026 (pinned to the
Tier 0 head manifest, `issued_at` 2026-10-13T00:36:38Z — never wall-clock)
**Proposed by:** David, Oct 12, 2026, 20:41 EDT — "making an ISO of the
kernel so we have a permanent restore across servers or to spawn and
copy new ones" ("colonel" in the voice-to-text was *kernel*).
**Context in his same breath:** the system goes live while still
honestly BETA; adoption is the need; the image is how the baton passes —
the system must be able to run beyond any single runner.

Grades: PROVEN (receipt in hand) · REPORTED (a named source says so) ·
INFERRED (derived, shown) · DESIGN (specified, unbuilt) · UNKNOWN
(named, not filled).

---

## 1. What the image IS

One versioned, hash-pinned artifact — `kernel-iso-v0.tar` — freezing the
kernel's FORM at the Tier 0 chain head:

- the white-ledger chain (`coin/ledger/GENESIS.md`,
  `coin/ledger/GROUND-CONTROL.md`) exactly as published at Tier 0;
- the signed head manifest over that chain
  (`coin/ledger/head-manifest.json`);
- the signed endpoint registry (`coin/endpoints.json`, seq 1) — the
  public doors a restored copy checks itself against;
- the public spec and the issuance law (`coin/spec/SPEC.md`,
  `coin/rules/ISSUANCE.md`);
- the published PUBLIC keys (`coin/keys/`) — verification material only;
- the verification + state engines of record: the sub-Merkle
  dual-pipeline verifier (`kernel/dualpipe.py`) and the deterministic
  folder (`kernel/fold.py`), plus the vendored pure-Python Ed25519
  verify primitive (`kernel/ed25519_pure.py`) so the image's own
  verifier needs nothing outside the image;
- the tooling that cuts and checks it (`build-iso.py`, `restore.py`)
  and this spec.

Every content file is listed in the in-image `MANIFEST.json` with its
SHA-256, byte count, and honest grade; the manifest payload is signed
under the house Ed25519 regime (transitional lane key — §4). The
manifest is the one file not listed in itself; its integrity comes from
its own signature plus the published release envelope (§6), which binds
the manifest's hash and the image's hash together.

- Grade: the contents EXIST and verify (PROVEN — `ISO-RECEIPT.md`);
  the kernel they form is DESIGN except where a file's own grade
  says otherwise, and the image says BETA on its face.

## 2. What the image is NOT

- **Not an identity.** The image contains no private keys, no seeds, no
  signing material of any kind — the commit guard's rule, applied to an
  artifact. It carries two PUBLIC keys because verification needs them;
  a public key lets a copy *check* the record, never *make* one.
- **Not an authority.** A restored or spawned copy cannot sign a head,
  cannot enroll a node, cannot issue anything (`rules/ISSUANCE.md`
  rides inside the image precisely so the refusal travels with the
  form). The head manifest inside is a *record signed elsewhere* —
  evidence, not a capability.
- **Not a deployment.** Cutting or copying the image changes no server,
  joins no network, and moves no value. Tier 1 (mesh) and Tier 2
  (gated) are untouched by it.

## 3. THE IDENTITY LAW (stated here as law)

**The ISO carries FORM, never identity.**

1. A copy of the image is *inert*: it can verify the chain, fold the
   state, and prove it matches the public record — and it is nobody
   while it does so.
2. A spawned copy becomes *someone* only when the enrollment ceremony
   (sovereign mesh, six steps — SUBMIT · GRADE · VERIFY · COLLAPSE ·
   WRITE-WHITE · WRITE-DARK; `~/workspace/sovereign-mesh/step0/mesh.py`)
   births its **own** Ed25519 key **on its own node** and admits it.
   The key is born there, or the node is not born at all.
3. **Copies are not different entities.** David's P-4 ruling
   (Oct 12, 2026): MultiSig and witnessing require two DIFFERENT
   entities. A thousand spawns of this image are one form in a
   thousand places — zero witnesses — until each holds a distinct,
   ceremony-born key. Nothing in the image lets a copy countersign
   itself into a second entity.
4. **A restore is a re-keying, never a cloning.** Restoring a node
   means: unpack the image, verify it against the public doors, then
   run the ceremony so the *same identity* is re-born with a fresh key
   on the restored node, the re-birth written to the white ledger as a
   superseding record anyone can check. A lost key is never recovered
   from an image, because no image ever held it.
5. The baton rule (David, Oct 12, 2026): "it's a relay and you can
   only run with the baton so far." The form is what passes. Whoever
   picks it up brings their own key, their own ceremony, their own
   name in the ledger.

## 4. Transitional honesty

The signing key behind the Tier 0 head manifest, the endpoint
registry, and this image's manifests is TRANSITIONAL — generated
on-lane pending David's owner-device ceremony. Every record it touches
is **LEGACY** and will be re-sealed when the ceremony key arms. The
image does not hide this: `key_status` rides in every manifest it
carries. When re-sealing happens, a new ISO version is cut from the
re-sealed record; v0 is never edited in place (versions are
append-only, like the ledger).

## 5. The BETA mark

The image, its in-image manifest, and its published release envelope
all carry `status: "BETA"` and the per-file grades of their contents.
BETA here means exactly what the record shows: the chain is real and
verifiable; the kernel is specified and partially prototyped; issuance
has not occurred; the launch is honest about all three. The mark is
not a disclaimer under the artifact — it is a field inside the signed
payload, so it cannot be quietly dropped without breaking the
signature.

## 6. Determinism contract + publication

`build-iso.py` assembles the image byte-deterministically:

- file set fixed by the spec (§1), paths sorted;
- every tar entry's mtime pinned to the head manifest's `issued_at`
  (2026-10-13T00:36:38Z), uid/gid 0, empty uname/gname, modes
  normalized (0644);
- the in-image manifest is generated from the staged bytes, signed,
  and embedded last in sort order but computed before sealing.

**A cut is valid only if two independent builds produce identical
SHA-256.** Otherwise the build refuses and no image is released.

Publication follows the Tier 0 pattern: the release envelope
(`ISO-MANIFEST.v0.json` — payload binds the image file name, image
SHA-256, image byte count, in-image manifest SHA-256, and the chain
head it freezes) is committed to `coin-repo/iso/`, pushed to the
GitHub mirror, and pinned to IPFS via Pinata. **The image itself stays
in `~/workspace/kernel-iso/`**: at v0 it is ~100 KB class, but the rule
is size discipline, not convenience — the published record is the
manifest + hashes; anyone holding the image can verify it against
them, and anyone holding only the manifest knows exactly which image
is the real one.

## 7. Restore + spawn semantics

**Restore** (any machine, no credentials): unpack → run `restore.py`
→ it verifies the manifest signature, every file hash, the chain
linkage, the head-manifest signature, and folds the state; with
`--fetch` it pulls the head manifest and entries from the public doors
(GitHub raw + the IPFS gateway named in the registry) and requires the
restored copy to reach the **identical chain head and fold hash** as
the live record. Anything less is a failed restore, said so.

**Spawn**: the same unpack + verify, and then a deliberate stop. The
copy is a faithful, verified *form* — and per §3 it waits, inert,
until a ceremony on its own node gives it a key and a name. The image
contains everything needed to verify and nothing needed to *be*
someone; that asymmetry is the design, not a gap.

Proofs for both — two independent clean-room unpacks reaching
identical head + fold state, and the full dual-pipe run over a
converted rendering of the chain in each room — are executed at cut
time and pasted, real output, into `ISO-RECEIPT.md`.

## 8. The v1 seam (named, not hidden)

W1 — the deterministic ledger kernel (coin-live DESIGN §4, build item
W1; W8 is its single-file packaging) — had **not** landed when v0 was
cut (`~/workspace/coin-live/W1-W8-RECEIPT.md` absent at cut time). V0
therefore freezes today's pieces: the published chain + the dual-pipe
verifier + the folder, exactly as they stand. When W1 lands:

- v1 swaps the W1 kernel in as the core under `kernel/`; dual-pipe
  becomes its verification layer and fold its state engine (the roles
  the coin-VM architecture already assigns them);
- `kernel/dualpipe.py`'s signing import (bound to the lane path
  `~/workspace/swarm-node`) is replaced by the image-local vendored
  primitive, making the whole verifier location-independent;
- a v1 image is cut, proven, and published the same way; v0 stays as
  the historical first cut. The identity law (§3) does not change.

*Spec ends. The image is BETA, the law is not.*
