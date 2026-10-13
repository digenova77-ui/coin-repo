# THE COIN REPOSITORY — canonical home (sovereign ground)

Doctrine (David, Oct 12, 2026): a repository is the **town square,
not the vault**.

## What lives here (the best)
- `spec/` — the coin system's public specification and design law.
- `ledger/` — the WHITE ledger: append-only public records. Every
  entry names the hash of the entry before it; every git commit is a
  receipt. Anyone may clone, recompute, and witness.
- `rules/` — issuance and governance rules, in the open.
- This repository is the CANONICAL original. GitHub (and any other
  host) may carry a MIRROR for distribution and witness — a mirror
  is a reflection, never the foundation. If every mirror vanished
  tomorrow, this record stands.

## What never lives here (the worst, thrown out — mechanically)
- Private keys, seed phrases, signing material, wallet files,
  credentials of any kind — in ANY repository, public or private,
  ours or anyone's. Git history is forever; a secret committed once
  is a secret published eventually.
- By the sovereign-bank principle: whoever has the token IS the
  bank. Keys stay with their holders, in wallets and ceremonies.
- Enforcement is mechanical, not a promise: `tools/guard.sh` runs
  as a pre-commit hook and REFUSES any commit carrying key-shaped
  material. The worst is thrown out by the gate, not by memory.

## Layers, kept distinct
CODE + RULES (public) · LEDGER (public, mirrored) · KEYS (never here)

## Verify it yourself (Tier 0, published Oct 12, 2026)
- `ledger/head-manifest.json` — the signed head of the white ledger
  (Ed25519, house regime; signer key in `keys/`). Recompute the
  SHA-256 of each ledger entry and compare: the chain is the receipt.
- `endpoints.json` — the signed endpoint registry (seq 1). The coin
  fetches hash-named things only; endpoints are data, never trust.
- `demo/` — DEMO surfaces, labeled on their faces and in `demo/README.md`.
  They move no value and sign nothing.
- Keys in `keys/` are TRANSITIONAL (on-lane, pending the owner-device
  ceremony); records they sign are LEGACY and will be re-sealed.
