#!/usr/bin/env python3
"""build_coinfile.py — assemble coin.py, the W8 one-file coin.

The coin-file is ONE self-contained Python file a person can hold:
the dual-pipe verifier + the W1 kernel fold + a pure-Python Ed25519
verify, with the published chain embedded (white-ledger entries, the
signed head manifest, the kernel chain + its checkpoints, the signed
endpoint registry, the public keys). Run it and it verifies the
published chain — locally, with no dependency on any server — and,
when online, fetches the current head manifest through the registry's
endpoints and compares (the P1 ping: a fetch, never a leash).

HOW IT IS BUILT (and why it can be trusted to be the same code):
the verifier and fold functions are extracted from their canonical
sources — ~/workspace/dual-pipe/dualpipe.py, kernel/kernel.py,
~/workspace/swarm-node/signing/ed25519_pure.py (verify-only; the
key-generation and signing functions are NOT carried) — by AST, not
re-typed. kernel/test_coinfile.py proves the assembled file's
verdicts agree with dualpipe.verify, and that building twice yields
byte-identical output (the build stamp is a hash of the embedded
data; no wall-clock enters the file).

Usage: build_coinfile.py [--chain PATH] [--checkpoints PATH]
                         [--out PATH] [--repo PATH]
Defaults: the repo's committed kernel chain and coin.py at repo root.
"""
import ast
import base64
import hashlib
import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DUALPIPE_SRC = os.path.expanduser("~/workspace/dual-pipe/dualpipe.py")
ED25519_SRC = os.path.expanduser("~/workspace/swarm-node/signing/ed25519_pure.py")

# Publication facts from the Tier 0 execution (TIER0-RECEIPT.md):
# where the signed endpoint registry itself can be fetched to check
# for a successor. Data, not trust — anything fetched is verified.
REGISTRY_URLS = [
    "https://raw.githubusercontent.com/digenova77-ui/coin-repo/main/endpoints.json",
    "https://ipfs.dualiscapax.ai/ipfs/QmeC7GXNqfLVH1BHv3u2poEr7nazv9obHEckNDS8F95frd",
]
RAW_BASE = "https://raw.githubusercontent.com/digenova77-ui/coin-repo/main/"


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def extract(path, keep_assigns=(), keep_defs=(), drop_defs=(),
            keep_all_assigns=False):
    """Emit the named top-level assignments/functions/classes from a
    source file, in source order, via ast.unparse (deterministic)."""
    with open(path, encoding="utf-8") as f:
        tree = ast.parse(f.read())
    out = []
    for node in tree.body:
        if isinstance(node, ast.Assign):
            names = [t.id for t in node.targets
                     if isinstance(t, ast.Name)]
            if keep_all_assigns or \
                    any(n in keep_assigns for n in names):
                out.append(ast.unparse(node))
        elif isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            if keep_defs and node.name in keep_defs:
                out.append(ast.unparse(node))
            elif drop_defs and node.name not in drop_defs:
                out.append(ast.unparse(node))
    return "\n\n\n".join(out)


HEADER = '''#!/usr/bin/env python3
"""coin.py — THE COIN, AS ONE FILE (W8).

One file, any computer with python3: hold it, run it, and it verifies
the published chain itself — the signed head manifest over the white
ledger, the dual-pipe verification of the kernel chain (Pipe V
content + Pipe A strand + the poles' cross-signed checkpoints), and
the fold that derives state from the sequence alone. Snapshots are
caches, never truth; this file re-folds everything it believes.

    python3 coin.py verify            local verdicts + head check
    python3 coin.py verify --offline  local verdicts only
    python3 coin.py state             the folded state + fold hash
    python3 coin.py info              what this file is

Online, `verify` also fetches the current head manifest through the
signed endpoint registry's doors and compares heads: AGREE, DIFFERS
(a validly signed different head — reported, not silently adopted),
INVALID (a fetched artifact that fails its checks — refused), or
UNKNOWN (unreachable — the local verdict stands; offline costs
freshness, never validity).

GRADES AND FENCES, on the face:
- This file verifies and folds. It issues NOTHING: the kernel it
  carries refuses issuance by construction (rules/ISSUANCE.md), the
  published ledger's supply is zero, and `peg_ratio_E` is UNDECIDED.
- Keys are TRANSITIONAL (on-lane, pending the owner-device
  ceremony); every record they sign is LEGACY and will be re-sealed.
- MSB status: UNRESOLVED. This file moves no value for anyone.
- Build stamp (sha256 of the embedded data): __STAMP__
- Sources it was assembled from (by AST extraction, not re-typing):
  dual-pipe verifier, W1 kernel fold, house pure-Python Ed25519
  (verify-only). Builder: tools/build_coinfile.py in coin-repo.
"""

import base64
import hashlib
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

'''

SHIM = '''

# ---------- verify backend shim (embedded pure Ed25519) ----------

class _Backend:
    """The house backend interface, verify-only, over the embedded
    pure-Python Ed25519 above. Raises BadSignature on any failure
    (the pure verify never returns False)."""

    @staticmethod
    def verify(pubkey, signature, message):
        return verify(signature, message, pubkey)


backend = _Backend()


class _DPShim:
    """The kernel fold speaks of `dp.` — bind it to the dual-pipe
    functions carried in this file."""


dp = _DPShim()
dp.canonical = canonical
dp.sha256 = sha256
dp.sha256b = sha256b
dp.entry_hash = entry_hash
dp.pipe_v = pipe_v
dp.VALID_KINDS = VALID_KINDS
dp.genesis_seed = genesis_seed
dp.backend = backend

'''

GLUE = '''

# ---------- the coin-file's own glue ----------

def run_dual_verification(entries, checkpoints, pubs):
    """The dual run over the embedded kernel chain — the same
    verdict composition as dualpipe.verify(mode="dual"): Pipe V AND
    Pipe A AND cross-attestation must all pass; divergence is named,
    never averaged away."""
    if not entries:
        return {"ok": False, "divergence": "CONTENT_FAILURE",
                "pipe_v": {"ok": False,
                           "failures": ["empty ledger: no genesis"]},
                "pipe_a": None, "cross": None}
    ledger = entries[0].get("ledger")
    v = pipe_v(entries, ledger)
    a = pipe_a(entries, ledger, quantum=KERNEL_QUANTUM,
               max_gap=KERNEL_MAX_GAP)
    refold = strand_fold(entries, ledger)
    cross_fails = cross_check(entries, ledger, v, a, checkpoints,
                              pubs, refold["states"])
    classes = [c for c, _ in cross_fails]
    if not v["ok"]:
        divergence = "CONTENT_FAILURE"
    elif not a["ok"]:
        divergence = "STRUCTURE_FAILURE"
    elif "POLE_DIVERGENCE" in classes:
        divergence = "POLE_DIVERGENCE"
    elif cross_fails:
        divergence = classes[0]
    else:
        divergence = None
    ok = bool(v["ok"] and a["ok"] and not cross_fails)
    return {"ok": ok, "divergence": divergence,
            "pipe_v": {"ok": v["ok"], "failures": v["failures"],
                       "root": v["root"], "head_seq": v["head_seq"]},
            "pipe_a": {"ok": a["ok"], "failures": a["failures"],
                       "strand_head": a["strand_head"]},
            "cross": {"ok": not cross_fails,
                      "failures": [f"{c}: {d}" for c, d in cross_fails]}}


def _lane_pub():
    return base64.b64decode(EMBEDDED["lane_pub_b64"])


def _embedded_files():
    return {name: base64.b64decode(b64)
            for name, b64 in EMBEDDED["entry_files_b64"].items()}


def _pipe_pubs():
    return {"v": base64.b64decode(EMBEDDED["pipe_pubs_b64"]["v"]),
            "a": base64.b64decode(EMBEDDED["pipe_pubs_b64"]["a"])}


def local_verdicts():
    """Everything this file can prove without any server."""
    lane = _lane_pub()
    manifest = verify_manifest_payload(
        EMBEDDED["manifest"], _embedded_files(), lane)
    registry = verify_registry_payload(EMBEDDED["registry"], lane)
    dual = run_dual_verification(
        EMBEDDED["kernel_entries"], EMBEDDED["kernel_checkpoints"],
        _pipe_pubs())
    settle_ok, settle_detail = settle_kernel(EMBEDDED["kernel_entries"])
    return {"manifest": manifest, "registry": registry, "dual": dual,
            "settle": {"ok": settle_ok, "detail": settle_detail},
            "ok": bool(manifest["ok"] and registry["ok"]
                       and dual["ok"] and settle_ok)}


def _fetch(url, timeout=20):
    req = urllib.request.Request(
        url, headers={"User-Agent": "dualiscapax-coin-file/1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def online_head_check(local):
    """The P1 ping: fetch the current head manifest through the
    registry's doors and compare with the embedded head. Returns a
    status dict; never raises, never adopts anything."""
    registry = EMBEDDED["registry"]
    urls = []
    for ep in registry.get("endpoints", []):
        if ep.get("role") == "ledger-head":
            urls.append(ep["url"])
            if ep.get("also_at"):
                urls.append(ep["also_at"])
    embedded_head = local["manifest"]["head_hash"]
    fetched = None
    used = None
    for url in urls:
        try:
            fetched = json.loads(_fetch(url).decode("utf-8"))
            used = url
            break
        except Exception:
            continue
    if fetched is None:
        return {"status": "UNKNOWN",
                "note": "no endpoint reachable — freshness unknown; "
                        "the local verdict stands"}
    # verify the fetched manifest in full: signature + entry hashes
    files = {}
    payload = fetched.get("payload", {})
    for e in payload.get("entries", []):
        try:
            files[e["file"]] = _fetch(EMBEDDED["raw_base"] + e["file"])
        except Exception:
            files = {}
            break
    if not files:
        return {"status": "UNKNOWN",
                "note": "manifest fetched but its entries were not — "
                        "cannot verify it; nothing adopted"}
    res = verify_manifest_payload(fetched, files, _lane_pub())
    if not res["ok"]:
        return {"status": "INVALID",
                "note": "fetched manifest FAILS verification — refused",
                "checks": res["checks"], "via": used}
    if res["head_hash"] == embedded_head:
        return {"status": "AGREE", "via": used,
                "head_hash": res["head_hash"]}
    return {"status": "DIFFERS", "via": used,
            "embedded_head": embedded_head,
            "fetched_head": res["head_hash"],
            "note": "a validly signed different head exists — "
                    "reported, not adopted; adoption is a governed "
                    "update, not a fetch"}


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    cmd = argv[1]
    if cmd == "info":
        st, fh = fold_kernel(EMBEDDED["kernel_entries"])
        print(json.dumps({
            "file": "coin.py — the coin as one file (W8)",
            "build_stamp": EMBEDDED["build_stamp"],
            "kernel_ledger": st["ledger"], "kernel_height": st["height"],
            "kernel_head": st["head"], "fold_hash": fh,
            "published_head": EMBEDDED["manifest"]["payload"]["head_hash"],
            "registry_seq": EMBEDDED["registry"]["registry_seq"],
            "supply_units": st["supply_units"],
            "key_status": "TRANSITIONAL / LEGACY",
            "issuance": "refused by construction (rules/ISSUANCE.md)",
            "msb": "UNRESOLVED"}, indent=2))
        return 0
    if cmd == "state":
        st, fh = fold_kernel(EMBEDDED["kernel_entries"])
        print(json.dumps({"state": st, "fold_hash": fh}, indent=2))
        return 0
    if cmd == "verify":
        local = local_verdicts()
        out = {"local": local}
        if "--offline" in argv:
            out["online"] = {"status": "SKIPPED (--offline)"}
        else:
            out["online"] = online_head_check(local)
        out["verdict"] = "VALID" if (
            local["ok"] and out["online"]["status"] in
            ("AGREE", "DIFFERS", "UNKNOWN", "SKIPPED (--offline)")) \\
            else "INVALID"
        print(json.dumps(out, indent=2))
        return 0 if out["verdict"] == "VALID" else 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
'''


def build(chain_path, checkpoints_path, out_path, repo):
    sys.path.insert(0, os.path.expanduser("~/workspace/swarm-node"))
    from signing.keys import dearmor_pubkey

    with open(os.path.join(repo, "ledger", "head-manifest.json"),
              encoding="utf-8") as f:
        manifest = json.load(f)
    with open(os.path.join(repo, "endpoints.json"),
              encoding="utf-8") as f:
        registry = json.load(f)
    entry_files = {}
    for e in manifest["payload"]["entries"]:
        with open(os.path.join(repo, e["file"]), "rb") as f:
            entry_files[e["file"]] = base64.b64encode(f.read()).decode()
    with open(chain_path, encoding="utf-8") as f:
        entries = [json.loads(line) for line in f if line.strip()]
    checkpoints = []
    if os.path.exists(checkpoints_path):
        with open(checkpoints_path, encoding="utf-8") as f:
            checkpoints = [json.loads(line) for line in f if line.strip()]
    with open(os.path.join(repo, "keys", "lane.pub"),
              encoding="utf-8") as f:
        lane_pub = dearmor_pubkey(f.read())
    pipe_pubs = {}
    for role, fname in (("v", "pipe-v.pub"), ("a", "pipe-a.pub")):
        with open(os.path.join(repo, "keys", fname),
                  encoding="utf-8") as f:
            pipe_pubs[role] = base64.b64encode(
                dearmor_pubkey(f.read())).decode()

    data = {"manifest": manifest, "entry_files_b64": entry_files,
            "kernel_entries": entries,
            "kernel_checkpoints": checkpoints,
            "registry": registry,
            "lane_pub_b64": base64.b64encode(lane_pub).decode(),
            "pipe_pubs_b64": pipe_pubs,
            "registry_urls": REGISTRY_URLS, "raw_base": RAW_BASE}
    stamp = hashlib.sha256(canonical(data)).hexdigest()
    data["build_stamp"] = stamp

    ed = extract(ED25519_SRC,
                 drop_defs={"generate_keypair", "publickey", "sign"},
                 keep_all_assigns=True)
    dual = extract(
        DUALPIPE_SRC,
        keep_assigns={"GENESIS_DOMAIN", "STRAND_DOMAIN", "VALID_KINDS",
                      "CHECKPOINT_EVERY", "DEFAULT_MAX_GAP",
                      "DEFAULT_QUANTUM"},
        keep_defs={"canonical", "sha256", "sha256b", "parse_ts",
                   "genesis_seed", "strand_seed", "entry_hash",
                   "merkle_root", "merkle_proof", "verify_merkle_proof",
                   "pipe_v", "twist", "strand_fold", "pipe_a",
                   "_sig_ok", "_row_hash", "cross_check"})
    kern = extract(
        os.path.join(repo, "kernel", "kernel.py"),
        keep_assigns={"LEDGER_NAME", "KERNEL_QUANTUM", "KERNEL_MAX_GAP",
                      "INVARIANTS", "INVARIANT_HASH", "ISSUANCE_KINDS",
                      "ISSUANCE_FIELDS"},
        keep_defs={"KernelError", "ChainError", "MisfoldError",
                   "IssuanceRefused", "AppendRefused", "_verify_sig",
                   "verify_manifest_payload", "verify_registry_payload",
                   "_issuance_field_hit", "screen_issuance",
                   "fold_kernel", "snapshot_kernel", "settle_kernel"})

    parts = [HEADER.replace("__STAMP__", stamp),
             "# ===== Ed25519 verify (house pure implementation; "
             "key generation and signing are NOT carried) =====\n\n" + ed,
             "\n\n# ===== the dual pipe (verification layer) =====\n\n"
             + dual,
             SHIM,
             "# ===== the W1 kernel fold =====\n\n" + kern,
             "\n\n# ===== embedded published chain =====\n\nEMBEDDED = "
             + repr(json.loads(canonical(data).decode("utf-8"))) + "\n",
             GLUE]
    text = "".join(parts)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(text)
    return {"out": out_path, "bytes": len(text.encode("utf-8")),
            "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "build_stamp": stamp}


def main(argv):
    args = {"chain": os.path.join(REPO, "kernel", "chain.jsonl"),
            "out": os.path.join(REPO, "coin.py"), "repo": REPO}
    args["checkpoints"] = args["chain"] + ".checkpoints.jsonl"
    for i, a in enumerate(argv):
        if a in ("--chain", "--checkpoints", "--out", "--repo") \
                and i + 1 < len(argv):
            args[a[2:]] = argv[i + 1]
    if "checkpoints" not in args or args["checkpoints"] == \
            os.path.join(REPO, "kernel", "chain.jsonl") + \
            ".checkpoints.jsonl":
        args["checkpoints"] = args["chain"] + ".checkpoints.jsonl"
    print(json.dumps(build(args["chain"], args["checkpoints"],
                           args["out"], args["repo"]), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
