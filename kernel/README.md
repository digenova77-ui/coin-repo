# THE KERNEL — W1 (built Oct 12, 2026)

The deterministic ledger kernel of the coin: build item **W1** of
`~/workspace/coin-live/DESIGN.md` §4, implementing the kernel_ledger
specification of `~/workspace/goals/idea-tracking/files/15-coin-vm-architecture.md` §1.

- `kernel.py` — the kernel. Append/verify over a hash-chained ledger;
  state derived **only** by folding (snapshots are caches, never
  truth); the verify path is the dual pipe (Pipe V + Pipe A +
  cross-signed checkpoints, integrated from `~/workspace/dual-pipe/`,
  not rebuilt); a Joule-meter seam (interface + MODELED placeholder —
  no invented measurements, W6 is unbuilt); **no network I/O**;
  **no issuance path** — issuance-shaped transitions are refused by
  construction, with tests proving the refusal (`rules/ISSUANCE.md`
  is law).
- `chain.jsonl` — the kernel chain. Entries 0–1 are imports of the
  published white ledger (`ledger/GENESIS.md`,
  `ledger/GROUND-CONTROL.md`), bound by the file hashes the signed
  head manifest attests. Entry 2 attests this build.
- `chain.jsonl.checkpoints.jsonl` — the poles' cross-signed
  checkpoints over the kernel chain (root + strand head, both
  signatures over one body).
- `test_kernel.py` — 15 tests: determinism (two kernels, and a
  from-scratch rebuild, byte-identical), dual-pipe tamper rejection,
  snapshot-lie rejection by re-fold, issuance refusal, the meter's
  honest MODELED grade, the no-network property.
- `test_coinfile.py` — the W8 coin-file's tests (byte-determinism of
  the build, offline verification, agreement with dualpipe.verify).

Run: `python3 kernel.py verify kernel/chain.jsonl` ·
`python3 kernel.py state kernel/chain.jsonl` ·
`python3 -m unittest test_kernel test_coinfile` (from this directory).

Grades: the kernel and its tests are REAL (they run, tonight). The
pole keys that co-sign checkpoints are the dual-pipe prototype's
(documented seam: both seeds in the dual-pipe vault, never in this
repo; public halves in `keys/`). Transaction-level grant signatures
are W2 — not built, not implied. The value instrument remains
behind its gates (spec §§8–9): nothing here issues anything.
