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

## The coin-file — DESIGN, not staged as a file

There is no coin file to hold yet, and this directory will not fake
one. The one-file world ("one file, any computer, open it and the
world boots") is specified in
`~/workspace/goals/idea-tracking/files/15-coin-vm-architecture.md`
§2 — the WASM/browser build is its demo path — and packaging it is
build item W8 (2–4 weeks) of `~/workspace/coin-live/DESIGN.md` §4.
What is staged here is the honest pointer, not a counterfeit boot.
When W8 lands, the file lands here, labeled, with its hash.
