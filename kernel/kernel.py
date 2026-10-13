#!/usr/bin/env python3
"""kernel.py — W1: the deterministic ledger kernel of the coin.

Build item W1 of ~/workspace/coin-live/DESIGN.md §4, implementing §1 of
~/workspace/goals/idea-tracking/files/15-coin-vm-architecture.md (the
kernel_ledger specification; the V2 sketch it grows from is REAL, this
implementation is the first code under it).

WHAT THE KERNEL IS
- A deterministic state machine over an append-only, hash-chained
  ledger. The ledger is the state; entries are transitions; agreement
  comes from re-execution, not from a validator council. There is no
  validator set, no Unique Node List, nothing to capture.
- State is derived ONLY by folding: `fold_kernel(entries)` is a pure
  function of the sequence. Snapshots are caches, never truth — a
  claimed state is believed only when a fresh fold from genesis
  reproduces it byte-exact (`settle_kernel`, the prion defense carried
  over from ~/workspace/folding-study/fold.py).
- The verify path is the DUAL PIPE (~/workspace/dual-pipe/, DONE,
  12/12): Pipe V (content) + Pipe A (the strand) + cross-signed
  checkpoint attestation, fail-closed with named divergences. The
  kernel integrates it; it does not rebuild it.
- The kernel bootstraps from the PUBLISHED white ledger: entry 0 and
  entry 1 of the kernel chain are imports of ledger/GENESIS.md and
  ledger/GROUND-CONTROL.md, each bound by the SHA-256 of its file
  bytes — the same hashes the signed head manifest attests.
- NO network I/O exists in this module. No socket, no urllib, no
  fetch of any kind. Freshness is other layers' work (the pings,
  DESIGN §2); validity is local math.

ISSUANCE — REFUSED BY CONSTRUCTION (rules/ISSUANCE.md is law)
- The kernel's grammar has no issuance kind. `screen_issuance` runs
  before grammar, before append, and again inside the fold: any
  issuance-shaped kind (ISSUE / MINT / EMISSION / ...) or any entry
  body carrying an issuance field (supply_delta, units_issued, ...)
  with a live value is refused — at append time as IssuanceRefused,
  inside a presented chain as MisfoldError.
- The fold's state carries `supply_units: 0` and NO fold branch can
  raise it. The chaperone asserts the invariant after every entry.
  There is no code path in this module that creates a unit.
- A TRANSFER naming a positive unit amount cannot fold either: no
  units exist to transfer. It is refused, never settled into a
  wrong state.

JOULE METER — A SEAM, NOT A NUMBER (W6 is unbuilt)
- `JouleMeter` is the interface; `ModeledJouleMeter` is the only
  implementation that exists. It returns joules=None, grade
  "MODELED", and says why. The kernel attaches a meter reading to
  every apply receipt — labeled, never invented.

KEYS
- The kernel signs nothing itself. Checkpoints are co-signed by the
  dual-pipe poles (seeds live in the dual-pipe vault, never in this
  repository — tools/guard.sh enforces it); the published white
  ledger's head is signed by the existing TRANSITIONAL lane key
  (fingerprint a271-8e62-3bff-02d2; records LEGACY). Transaction-level
  grant signatures are W2, not built here, and nothing in this module
  pretends otherwise.

House patterns: canonical JSON + sha256 throughout; timestamps enter
ONLY as entry data (the VM rule: no wall-clock reads inside the
transition function — apply() takes ts as an input).
"""
import base64
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.expanduser("~/workspace/dual-pipe"))
import dualpipe as dp  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CHAIN = os.path.join(REPO, "kernel", "chain.jsonl")

LEDGER_NAME = "coin-kernel"
# Cadence envelope for THIS ledger, declared: entries are publications
# (human-paced), not ticks. quantum MUST stay 1 — the dual-pipe cross
# phase refolds the strand with canonical parameters (quantum 1), and
# a kernel quantum other than 1 would make honest chains diverge.
KERNEL_QUANTUM = 1
KERNEL_MAX_GAP = 31 * 86400  # 31 days, in seconds

# The invariants every kernel entry binds by hash. If the invariants
# break, the transition dies (VM architecture §1).
INVARIANTS = {
    "append_only": True,
    "fold_only_state": True,
    "issuance": "REFUSED-BY-CONSTRUCTION (rules/ISSUANCE.md)",
    "supply_units": 0,
}
INVARIANT_HASH = dp.sha256(dp.canonical(INVARIANTS))

# Issuance-shaped kinds and body fields. There is deliberately no
# legitimate member of either set anywhere in the kernel grammar.
ISSUANCE_KINDS = {"ISSUE", "ISSUANCE", "MINT", "EMISSION", "EMIT",
                  "CREATE_UNITS", "INFLATE", "SEIGNIORAGE"}
ISSUANCE_FIELDS = {"supply_delta", "units_issued", "issue_units",
                   "mint_units", "new_supply", "emission",
                   "units_created", "create_units"}


class KernelError(Exception):
    """Base class for kernel refusals."""


class ChainError(KernelError):
    """The sequence itself is broken: bad link, bad hash, bad order."""


class MisfoldError(KernelError):
    """The sequence is intact but does not fold: an invariant refused it."""


class IssuanceRefused(KernelError):
    """An issuance-shaped transition was presented. There is no path."""


class AppendRefused(KernelError):
    """The chain refused an append (unverified chain, duplicate id)."""


def _verify_sig(pub, sig, msg):
    """Ed25519 verify -> bool (house backend; never raises out)."""
    try:
        dp.backend.verify(pub, sig, msg)
        return True
    except Exception:
        return False


# ---------- the published white ledger, verified pure ----------

def verify_manifest_payload(manifest, files, lane_pub):
    """Verify the signed head manifest against the entry files' bytes.

    manifest: parsed ledger/head-manifest.json (envelope form).
    files: {repo-relative path: file bytes} for every payload entry.
    lane_pub: 32-byte Ed25519 public key of the manifest signer.
    Pure: no I/O. Returns {ok, checks, head_hash, genesis_hash}."""
    checks = {}
    payload = manifest.get("payload", {})
    entries = payload.get("entries", [])
    ok = True
    prev_hash = None
    for i, e in enumerate(entries):
        data = files.get(e.get("file"))
        if data is None:
            checks[f"entry_{i}_present"] = False
            ok = False
            continue
        h = dp.sha256(data)
        good = (h == e.get("hash"))
        checks[f"entry_{i}_hash"] = good
        ok = ok and good
        if i > 0:
            link = (e.get("prev_hash") == prev_hash)
            checks[f"entry_{i}_link"] = link
            ok = ok and link
        prev_hash = e.get("hash")
    if entries:
        head_ok = payload.get("head_hash") == entries[-1].get("hash")
        gen_ok = payload.get("genesis_hash") == entries[0].get("hash")
        height_ok = payload.get("height") == entries[-1].get("entry")
    else:
        head_ok = gen_ok = height_ok = False
    checks["head_hash"] = head_ok
    checks["genesis_hash"] = gen_ok
    checks["height"] = height_ok
    ok = ok and head_ok and gen_ok and height_ok
    try:
        sig = base64.b64decode(manifest["sig"])
        sig_ok = _verify_sig(lane_pub, sig, dp.canonical(payload))
    except Exception:
        sig_ok = False
    checks["signature"] = sig_ok
    ok = ok and sig_ok
    return {"ok": ok, "checks": checks,
            "head_hash": payload.get("head_hash"),
            "genesis_hash": payload.get("genesis_hash")}


def verify_registry_payload(registry, lane_pub):
    """Verify the signed endpoint registry (endpoints.json): Ed25519
    over the canonical registry minus its signature block. Pure."""
    core = {k: v for k, v in registry.items() if k != "signature"}
    try:
        sig = base64.b64decode(registry["signature"]["sig"])
        sig_ok = _verify_sig(lane_pub, sig, dp.canonical(core))
    except Exception:
        sig_ok = False
    return {"ok": sig_ok, "signature": sig_ok,
            "registry_seq": registry.get("registry_seq"),
            "prev_registry_hash": registry.get("prev_registry_hash")}


# ---------- the issuance screen (runs everywhere, always) ----------

def _issuance_field_hit(body, depth=0):
    """Name of the first live issuance field in a body, or None.
    A field counts as live when its value is not None/0/False/'' —
    an explicitly zeroed field is a record, not an issuance."""
    if not isinstance(body, dict):
        return None
    for k, v in body.items():
        if k in ISSUANCE_FIELDS and v not in (None, 0, False, ""):
            return k
        if depth == 0 and isinstance(v, dict):
            hit = _issuance_field_hit(v, depth + 1)
            if hit:
                return hit
    return None


def screen_issuance(kind, body):
    """Refuse issuance-shaped transitions. Raises IssuanceRefused.
    Called by apply() before anything else, and by the fold as the
    chaperone's first check on every entry."""
    if isinstance(kind, str) and kind.upper() in ISSUANCE_KINDS:
        raise IssuanceRefused(
            f"kind {kind!r} is issuance-shaped — the kernel has no "
            f"issuance path (rules/ISSUANCE.md)")
    hit = _issuance_field_hit(body or {})
    if hit:
        raise IssuanceRefused(
            f"body field {hit!r} is issuance-shaped — refused by "
            f"construction (rules/ISSUANCE.md)")


# ---------- the fold (state is a pure function of the sequence) ----------

def fold_kernel(entries):
    """Fold the kernel chain into state. Returns (state, fold_hash).

    The chaperone rides inside: it verifies the content chain first
    (Pipe V's checks, via the dual-pipe module), then guards every
    transition — issuance screen, kind grammar, the no-units rule —
    and writes nothing itself. A sequence that breaks an invariant
    does not settle into a wrong state; it is refused (MisfoldError).
    """
    if not entries:
        raise ChainError("empty chain: no genesis")
    ledger = entries[0].get("ledger")
    v = dp.pipe_v(entries, ledger)
    if not v["ok"]:
        raise ChainError("content chain broken: " + "; ".join(v["failures"]))
    state = {"ledger": ledger, "height": -1, "head": None,
             "genesis": None, "anchors": [], "pins": {},
             "attestations": {}, "votes": {}, "refusals": [],
             "migrations": [], "retirements": [], "plus_ones": 0,
             "counts": {}, "supply_units": 0}
    for e in entries:
        kind, body, seq = e.get("kind"), e.get("body") or {}, e.get("seq")
        try:
            screen_issuance(kind, body)
        except IssuanceRefused as ex:
            raise MisfoldError(
                f"seq {seq}: {ex} — this sequence does not fold")
        if kind not in dp.VALID_KINDS:
            raise MisfoldError(f"seq {seq}: unknown kind {kind!r}")
        state["counts"][kind] = state["counts"].get(kind, 0) + 1
        if kind == "GENESIS":
            if seq != 0 or state["genesis"] is not None:
                raise MisfoldError(f"seq {seq}: GENESIS out of place")
            state["genesis"] = {"entry_id": e["entry_id"],
                                "hash": e["hash"],
                                "source_sha256": body.get("source_sha256")}
        elif kind == "ANCHOR":
            state["anchors"].append(
                {"seq": seq, "entry_id": e["entry_id"], "hash": e["hash"],
                 "source_sha256": body.get("source_sha256")})
        elif kind == "PIN_RECEIPT":
            state["pins"][e["entry_id"]] = body.get("cid")
        elif kind == "AUDIT_ATTEST":
            state["attestations"][e["entry_id"]] = e.get("actor")
        elif kind == "VOTE":
            state["votes"][e["entry_id"]] = body
        elif kind in ("REFUSAL", "DOUBLE_VOTE_REJECTED"):
            state["refusals"].append(e["entry_id"])
        elif kind == "MIGRATION":
            state["migrations"].append(e["entry_id"])
        elif kind == "RETIREMENT":
            state["retirements"].append(e["entry_id"])
        elif kind == "PLUS_ONE":
            state["plus_ones"] += 1
        elif kind == "TRANSFER":
            # No units exist — by law, not by balance. A transfer
            # naming a positive amount of anything unit-shaped cannot
            # fold in a ledger whose supply is zero by construction.
            for key in ("amount", "units", "value"):
                amt = body.get(key)
                if isinstance(amt, (int, float)) and \
                        not isinstance(amt, bool) and amt > 0:
                    raise MisfoldError(
                        f"seq {seq}: TRANSFER names {key}={amt} but no "
                        f"units exist (supply is 0 by construction) — "
                        f"refused, never settled")
            # a record-only transfer (no positive amount) folds as a note
        if e.get("invariant_hash") != INVARIANT_HASH:
            raise MisfoldError(
                f"seq {seq}: invariant_hash does not match the kernel "
                f"invariants — this entry was not written under them")
        if state["supply_units"] != 0:
            raise MisfoldError(
                f"seq {seq}: INVARIANT BROKEN — supply_units is "
                f"{state['supply_units']}, must be 0")
        state["height"] = seq
        state["head"] = e["hash"]
    head = entries[-1]["hash"]
    fold_hash = dp.sha256(dp.canonical(state) + b"|" + head.encode("ascii"))
    return state, fold_hash


def snapshot_kernel(entries):
    """A snapshot is a CLAIM about the fold. It carries no authority."""
    state, fold_hash = fold_kernel(entries)
    return {"state": state, "fold_hash": fold_hash,
            "head": entries[-1]["hash"]}


def settle_kernel(entries, claimed=None):
    """Re-fold from genesis. A claimed snapshot is believed only if
    the fresh fold reproduces it byte-exact — state AND fold_hash.
    Returns (ok, fold_hash_or_reason). The prion defense."""
    try:
        state, fold_hash = fold_kernel(entries)
    except (ChainError, MisfoldError) as ex:
        return False, f"sequence does not settle: {ex}"
    if claimed is not None:
        if claimed.get("fold_hash") != fold_hash or \
                dp.canonical(claimed.get("state")) != dp.canonical(state):
            return False, (
                "snapshot REJECTED: re-fold does not reproduce it — "
                "a snapshot is a cache, never truth "
                "(template corruption refused)")
    return True, fold_hash


# ---------- the Joule meter seam (interface + MODELED placeholder) ----------

class JouleMeter:
    """The meter interface (W6's seat). A real meter measures the
    kernel's own compute per transition and feeds Ground Control's
    base quantity. Until one exists, nothing here invents a figure."""

    def meter(self, op, detail=None):
        raise NotImplementedError("no Joule meter exists yet (W6)")


class ModeledJouleMeter(JouleMeter):
    """The only implementation that exists: an honest placeholder.
    joules is None — not zero, not estimated: unmeasured."""

    def meter(self, op, detail=None):
        return {"op": op, "joules": None, "grade": "MODELED",
                "note": "no Joule meter exists (W6 unbuilt); this "
                        "reading is a labeled placeholder, not a "
                        "measurement"}


# ---------- sealing (the dual pipe's checkpoints, kernel envelope) ----------

def ensure_pipes():
    """The poles' keypairs live in the dual-pipe vault (never here).
    Born by the dual-pipe module's own init if the vault is fresh —
    the documented prototype seam: both poles' seeds in one vault."""
    if not os.path.exists(os.path.join(dp.VAULT, "pipes.json")):
        dp.init_pipes()


def seal_kernel(path, entries):
    """Append cross-signed checkpoints (both poles sign ONE body
    binding root AND strand head) under the kernel's declared
    cadence envelope. Mirrors dualpipe.seal with parameterized
    Pipe A — same checkpoint format, so dualpipe.verify reads them.
    Idempotent at an unchanged head; refuses to re-seal over a
    rewritten history."""
    ensure_pipes()
    ledger = dp.ledger_name_of(entries, path)
    v = dp.pipe_v(entries, ledger)
    a = dp.pipe_a(entries, ledger, quantum=KERNEL_QUANTUM,
                  max_gap=KERNEL_MAX_GAP)
    if not v["ok"]:
        raise AppendRefused(f"refusing to seal: Pipe V fails: {v['failures']}")
    if not a["ok"]:
        raise AppendRefused(f"refusing to seal: Pipe A fails: {a['failures']}")
    existing = dp.read_checkpoints(path)
    prev_cp = existing[-1]["row_hash"] if existing else None
    have = {r["body"]["seq"] for r in existing}
    head_seq = entries[-1]["seq"]
    want = {s for s in range(len(entries))
            if (s + 1) % dp.CHECKPOINT_EVERY == 0}
    want.add(head_seq)
    v_seed = dp._read_seed("pipe-v.seed")
    a_seed = dp._read_seed("pipe-a.seed")
    made = []
    for s in sorted(want):
        root_s = dp.merkle_root([e["hash"] for e in entries[:s + 1]])
        strand_s = a["states"][s]
        if s in have:
            row = next(r for r in existing if r["body"]["seq"] == s)
            if row["body"]["root"] != root_s or \
                    row["body"]["strand_head"] != strand_s:
                raise AppendRefused(
                    f"checkpoint at seq {s} already attests different "
                    f"state — history was rewritten under a seal; "
                    f"refusing to re-seal over it")
            prev_cp = row["row_hash"]
            continue
        body = dp._checkpoint_body(ledger, s, root_s, strand_s, prev_cp)
        msg = dp.canonical(body)
        v_sig = base64.b64encode(dp.backend.sign(v_seed, msg)).decode()
        a_sig = base64.b64encode(dp.backend.sign(a_seed, msg)).decode()
        row = {"body": body, "v_sig": v_sig, "a_sig": a_sig,
               "row_hash": dp._row_hash(body, v_sig, a_sig)}
        with open(dp.checkpoints_path(path), "a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
        prev_cp = row["row_hash"]
        made.append(s)
    return {"sealed_checkpoints": made, "head_seq": head_seq,
            "root": v["root"], "strand_head": a["strand_head"]}


# ---------- the kernel ----------

def _make_entry(entries, entry_id, kind, actor, body, ts):
    """Construct the next entry under the kernel invariants. Pure in
    its inputs — ts is data (VM rule), never a wall-clock read here."""
    if entries:
        head = entries[-1]
        seq, prev = head["seq"] + 1, head["hash"]
    else:
        seq, prev = 0, dp.genesis_seed(LEDGER_NAME)
    entry = {"v": 1, "ledger": LEDGER_NAME, "seq": seq, "ts": ts,
             "entry_id": entry_id, "kind": kind, "actor": actor,
             "body": body, "prev": prev,
             "invariant_hash": INVARIANT_HASH}
    entry["hash"] = dp.entry_hash(entry)
    return entry


class Kernel:
    """The deterministic ledger kernel over one chain file."""

    def __init__(self, chain_path=DEFAULT_CHAIN, meter=None):
        self.chain_path = chain_path
        self.meter = meter if meter is not None else ModeledJouleMeter()
        self.entries = dp.read_entries(chain_path) \
            if os.path.exists(chain_path) else []

    # -- verify: the dual pipe is the verify path --
    def verify(self):
        """Dual-pipe verification of the chain as it stands on disk:
        Pipe V + Pipe A + cross-attestation, fail-closed, divergences
        named. Returns dualpipe.verify's verdict dict."""
        return dp.verify(self.chain_path, mode="dual",
                         a_quantum=KERNEL_QUANTUM,
                         a_max_gap=KERNEL_MAX_GAP)

    def state(self):
        """Current state — folded fresh from the sequence, always."""
        return fold_kernel(self.entries)

    def snapshot(self):
        return snapshot_kernel(self.entries)

    def settle(self, claimed=None):
        return settle_kernel(self.entries, claimed)

    # -- the transition function --
    def apply(self, tx):
        """apply(state, tx) -> receipt | refusal (raised).

        tx: {"entry_id", "kind", "actor", "body", "ts"} — ts is
        signed-input-style data; the kernel never reads a clock.
        Order of refusal: issuance screen FIRST (by construction),
        then chain verification (never extend an unverified chain),
        then the fold of the candidate chain (the chaperone), and
        only then the append + seal. Deterministic: the same chain
        and the same tx produce the same entry hash and fold hash
        on any machine."""
        kind = tx.get("kind")
        body = tx.get("body") or {}
        screen_issuance(kind, body)  # raises IssuanceRefused
        if self.entries:
            verdict = self.verify()
            if not verdict["ok"]:
                raise AppendRefused(
                    f"chain does not dual-verify "
                    f"({verdict.get('divergence')}): refusing to extend it")
            for e in self.entries:
                if e.get("entry_id") == tx.get("entry_id"):
                    raise AppendRefused(
                        f"duplicate entry_id {tx.get('entry_id')!r}")
        entry = _make_entry(self.entries, tx["entry_id"], kind,
                            tx.get("actor", "kernel"), body, tx["ts"])
        candidate = self.entries + [entry]
        _state, fold_hash = fold_kernel(candidate)  # chaperone; may refuse
        os.makedirs(os.path.dirname(os.path.abspath(self.chain_path)),
                    exist_ok=True)
        with open(self.chain_path, "a", encoding="utf-8") as f:
            f.write(dp.canonical(entry).decode("utf-8") + "\n")
        self.entries = candidate
        seal = seal_kernel(self.chain_path, self.entries)
        reading = self.meter.meter(
            "apply", {"seq": entry["seq"], "kind": kind})
        return {"seq": entry["seq"], "entry_id": entry["entry_id"],
                "hash": entry["hash"], "tx_id": entry["hash"],
                "invariant_hash": INVARIANT_HASH,
                "fold_hash": fold_hash, "seal": seal, "meter": reading}

    # -- bootstrap from the published white ledger --
    @classmethod
    def bootstrap(cls, chain_path=DEFAULT_CHAIN, repo=REPO,
                  ts="2026-10-13T00:00:00Z", meter=None):
        """Verify the published white ledger (manifest signature +
        entry file hashes, pure checks), then import its entries as
        kernel entries 0 (GENESIS) and 1 (ANCHOR), bound by the file
        hashes the manifest attests. Refuses to bootstrap over an
        existing chain."""
        if os.path.exists(chain_path) and os.path.getsize(chain_path) > 0:
            raise AppendRefused(
                f"chain {chain_path} already exists — refusing to "
                f"re-bootstrap over it")
        manifest_path = os.path.join(repo, "ledger", "head-manifest.json")
        with open(manifest_path, encoding="utf-8") as f:
            manifest = json.load(f)
        from signing.keys import dearmor_pubkey
        with open(os.path.join(repo, "keys", "lane.pub"),
                  encoding="utf-8") as f:
            lane_pub = dearmor_pubkey(f.read())
        files = {}
        for e in manifest["payload"]["entries"]:
            with open(os.path.join(repo, e["file"]), "rb") as fb:
                files[e["file"]] = fb.read()
        result = verify_manifest_payload(manifest, files, lane_pub)
        if not result["ok"]:
            raise ChainError(
                f"published white ledger does not verify: {result['checks']}")
        payload = manifest["payload"]
        by_file = {e["file"]: e for e in payload["entries"]}
        gen = by_file["ledger/GENESIS.md"]
        gc = by_file["ledger/GROUND-CONTROL.md"]
        e0 = _make_entry([], "coin-genesis", "GENESIS", "kernel-bootstrap",
                         {"import": "published white-ledger genesis, "
                                    "bound by file hash",
                          "source_file": "ledger/GENESIS.md",
                          "source_sha256": gen["hash"],
                          "source_date": "2026-10-12",
                          "head_manifest": "ledger/head-manifest.json",
                          "manifest_head_hash": payload["head_hash"]}, ts)
        e1 = _make_entry([e0], "ground-control", "ANCHOR",
                         "kernel-bootstrap",
                         {"import": "published white-ledger entry 1, "
                                    "bound by file hash",
                          "source_file": "ledger/GROUND-CONTROL.md",
                          "source_sha256": gc["hash"],
                          "source_date": "2026-10-12",
                          "doctrine": "GROUND CONTROL, NOT ESCROW",
                          "peg_ratio_E": "UNDECIDED"}, ts)
        os.makedirs(os.path.dirname(os.path.abspath(chain_path)),
                    exist_ok=True)
        dp.write_entries(chain_path, [e0, e1])
        k = cls(chain_path, meter=meter)
        seal_kernel(chain_path, k.entries)
        return k


# ---------- CLI ----------

def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    cmd = argv[1]
    chain = argv[2] if len(argv) > 2 else DEFAULT_CHAIN
    if cmd == "bootstrap":
        ts = argv[3] if len(argv) > 3 else dp.now_iso()
        k = Kernel.bootstrap(chain, ts=ts)
        print(json.dumps({"bootstrapped": chain,
                          "head_seq": k.entries[-1]["seq"],
                          "head": k.entries[-1]["hash"]}, indent=2))
    elif cmd == "verify":
        k = Kernel(chain)
        r = k.verify()
        print(json.dumps(r, indent=2))
        return 0 if r["ok"] else 1
    elif cmd == "state":
        k = Kernel(chain)
        state, fold_hash = k.state()
        print(json.dumps({"state": state, "fold_hash": fold_hash},
                         indent=2))
    elif cmd == "apply" and len(argv) > 3:
        k = Kernel(chain)
        tx = json.loads(argv[3])
        if "ts" not in tx:
            tx["ts"] = dp.now_iso()
        try:
            print(json.dumps(k.apply(tx), indent=2))
        except KernelError as ex:
            print(json.dumps({"refused": f"{type(ex).__name__}: {ex}"},
                             indent=2))
            return 1
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
