# DEMOS — read the label first

Everything in this directory is a **DEMO**. It demonstrates shape and
feel. It moves no value, signs nothing, and connects to nothing.

## unity-wallet.html — the wallet face, DEMO

- The wallet as it exists today: a face. State lives in the browser's
  localStorage; the page makes **zero** network calls and performs
  **zero** signing (verifiable: no `fetch`, no `WebSocket`, no
  `XMLHttpRequest` in the source).
- Its own face says so, in its own words: *"Local demo — not sealed"*
  and *"this is a local demo identity — real format, real derivation"*
  — the bind-then-validate ceremony has not run for it, and it does
  not pretend otherwise.
- Byte-identical to the original of Oct 4, 2026
  (`~/workspace/your_files/unity-wallet/unity-wallet.html`):
  SHA-256 `61bd25490006527bc6855bdf8d536c1cca55790105c0022f0f2f0fc753f1673c`,
  44,578 bytes. The staged copy is the artifact, not a retouching.
- Grade: PROVEN as a demo surface. A working wallet stands on the
  unbuilt kernel (spec §4; build items W1–W8 of the coin-live design)
  — weeks of engineering, buildable now, not built yet.

## The coin-file — W8, built Oct 12, 2026

The coin file exists now: `coin.py`, at the root of this repo. It is
not in `demo/` because it is not a demo surface — it is the working
verifier form of the coin: one self-contained file (python3, stdlib
only) carrying the dual-pipe verifier, the W1 kernel fold, and the
published chain. Run `python3 coin.py verify` and it checks the
signed head manifest, the kernel chain's cross-signed checkpoints,
and the fold — locally, no server needed — and fetches the current
head through the endpoint registry to compare. It issues nothing,
moves no value, and its build is byte-deterministic: rebuild it with
`tools/build_coinfile.py` and the SHA-256 matches
(`cb6ea5453e5df9b39fb9eb98f80b125cb27ba98cb49a11d16505018425432855`
at this publication). The richer forms of the one-file world in
`15-coin-vm-architecture.md` §2 (native binaries per platform, the
WASM/browser build) remain DESIGN.
