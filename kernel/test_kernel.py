#!/usr/bin/env python3
"""Tests for the W1 ledger kernel (kernel.py).

What is proven here, in the house manner:
- determinism: two independent kernels over the same chain — and a
  from-scratch rebuild with the same inputs — produce byte-identical
  state and fold hashes;
- the verify path is the dual pipe: tampering that content-only
  checks pass is rejected with a named divergence;
- a lying snapshot is rejected by re-fold (the prion defense);
- issuance is refused BY CONSTRUCTION — at the screen, at append,
  and inside a presented chain's fold — and no state can carry supply;
- the bootstrap genuinely binds the published white ledger (the
  hashes in the kernel chain are the signed manifest's hashes);
- the Joule meter seam reports MODELED and invents no number;
- the kernel module contains no network I/O.

Run: python3 -m unittest test_kernel -v   (from ~/workspace/coin-repo/kernel)
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kernel as K  # noqa: E402
import dualpipe as dp  # noqa: E402

TS0 = "2026-10-13T00:00:00Z"


def ts(sec):
    return f"2026-10-13T00:00:{sec:02d}Z"


SCRIPT = [
    {"entry_id": "pin-spec", "kind": "PIN_RECEIPT", "actor": "w1-test",
     "body": {"cid": "QmTestSpec", "subject": "spec/SPEC.md"}, "ts": ts(10)},
    {"entry_id": "attest-build", "kind": "AUDIT_ATTEST", "actor": "w1-test",
     "body": {"subject": "W1 kernel test chain"}, "ts": ts(20)},
    {"entry_id": "note-vote", "kind": "VOTE", "actor": "w1-test",
     "body": {"question": "ship the kernel?", "vote": "pure logic"},
     "ts": ts(30)},
    {"entry_id": "refuse-1", "kind": "REFUSAL", "actor": "w1-test",
     "body": {"subject": "a bad idea, refused on the record"}, "ts": ts(40)},
]


def build_chain(chain_path):
    """Bootstrap from the real published repo (read-only on the repo;
    the chain file lives wherever chain_path says) and apply SCRIPT."""
    k = K.Kernel.bootstrap(chain_path, ts=TS0)
    for tx in SCRIPT:
        k.apply(dict(tx))
    return k


def recompute_chain(entries):
    """Attacker's tool (from the dual-pipe tests): rewrite prev-links
    and hashes so the presented chain is fully self-consistent."""
    out = []
    prev = dp.genesis_seed(entries[0]["ledger"])
    for e in entries:
        e = dict(e)
        e["prev"] = prev
        e.pop("hash", None)
        e["hash"] = dp.entry_hash(e)
        out.append(e)
        prev = e["hash"]
    return out


class KernelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.chain = os.path.join(cls._tmp.name, "chain.jsonl")
        cls.k = build_chain(cls.chain)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    # ---- bootstrap binds the published ledger ----

    def test_bootstrap_binds_published_hashes(self):
        with open(os.path.join(K.REPO, "ledger", "head-manifest.json")) as f:
            manifest = json.load(f)
        e0, e1 = self.k.entries[0], self.k.entries[1]
        self.assertEqual(e0["kind"], "GENESIS")
        self.assertEqual(e0["body"]["source_sha256"],
                         manifest["payload"]["genesis_hash"])
        self.assertEqual(e1["kind"], "ANCHOR")
        self.assertEqual(e1["body"]["source_sha256"],
                         manifest["payload"]["head_hash"])
        self.assertEqual(e1["prev"], e0["hash"])

    def test_honest_chain_dual_verifies(self):
        r = self.k.verify()
        self.assertTrue(r["ok"], r)
        self.assertTrue(r["anchored"])
        self.assertIsNone(r["divergence"])

    # ---- determinism ----

    def test_two_kernels_identical_state(self):
        k2 = K.Kernel(self.chain)
        s1, h1 = self.k.state()
        s2, h2 = k2.state()
        self.assertEqual(dp.canonical(s1), dp.canonical(s2))
        self.assertEqual(h1, h2)

    def test_rebuild_from_scratch_identical(self):
        other = os.path.join(self._tmp.name, "chain2.jsonl")
        k2 = build_chain(other)
        s1, h1 = self.k.state()
        s2, h2 = k2.state()
        self.assertEqual([e["hash"] for e in self.k.entries],
                         [e["hash"] for e in k2.entries])
        self.assertEqual(dp.canonical(s1), dp.canonical(s2))
        self.assertEqual(h1, h2)

    # ---- tamper rejection via the dual pipe ----

    def test_substitution_rejected_by_dual_pipe(self):
        path = os.path.join(self._tmp.name, "tampered.jsonl")
        entries = dp.read_entries(self.chain)
        entries[3]["body"] = {"cid": "QmAttacker", "subject": "spec/SPEC.md"}
        dp.write_entries(path, recompute_chain(entries))
        with open(dp.checkpoints_path(self.chain)) as f:
            cps = f.read()
        with open(dp.checkpoints_path(path), "w") as f:
            f.write(cps)
        k = K.Kernel(path)
        # content-only verification passes the recomputed chain...
        self.assertTrue(dp.verify(path, mode="v")["ok"])
        # ...the dual pipe — the kernel's verify path — does not.
        r = k.verify()
        self.assertFalse(r["ok"])
        self.assertIn(r["divergence"],
                      ("STRAND_ANCHOR_MISMATCH", "ROOT_ANCHOR_MISMATCH"))
        # and the kernel refuses to extend a chain that does not verify
        with self.assertRaises(K.AppendRefused):
            k.apply({"entry_id": "x", "kind": "PLUS_ONE",
                     "actor": "attacker", "body": {}, "ts": ts(50)})

    def test_naive_tamper_fails_fold(self):
        entries = dp.read_entries(self.chain)
        entries[2]["body"] = {"cid": "QmForged"}
        with self.assertRaises(K.ChainError):
            K.fold_kernel(entries)

    # ---- snapshot lies rejected by re-fold ----

    def test_honest_snapshot_settles(self):
        snap = self.k.snapshot()
        ok, fh = self.k.settle(snap)
        self.assertTrue(ok, fh)

    def test_lying_snapshot_rejected(self):
        snap = self.k.snapshot()
        lying = json.loads(dp.canonical(snap).decode())
        lying["state"]["supply_units"] = 1_000_000  # the prion's lie
        ok, reason = self.k.settle(lying)
        self.assertFalse(ok)
        self.assertIn("snapshot REJECTED", reason)
        lying2 = json.loads(dp.canonical(snap).decode())
        lying2["state"]["anchors"] = []  # a quieter lie: erase history
        ok2, _ = self.k.settle(lying2)
        self.assertFalse(ok2)

    # ---- issuance refused by construction ----

    def test_issuance_kinds_refused(self):
        for kind in ("MINT", "ISSUE", "ISSUANCE", "EMISSION"):
            with self.assertRaises(K.IssuanceRefused, msg=kind):
                self.k.apply({"entry_id": f"bad-{kind}", "kind": kind,
                              "actor": "attacker",
                              "body": {"units": 100}, "ts": ts(50)})

    def test_issuance_fields_refused(self):
        with self.assertRaises(K.IssuanceRefused):
            self.k.apply({"entry_id": "bad-field", "kind": "ANCHOR",
                          "actor": "attacker",
                          "body": {"supply_delta": 100}, "ts": ts(50)})
        with self.assertRaises(K.IssuanceRefused):
            self.k.apply({"entry_id": "bad-nested", "kind": "ANCHOR",
                          "actor": "attacker",
                          "body": {"meta": {"units_issued": 5}},
                          "ts": ts(50)})

    def test_issuance_inside_presented_chain_misfolds(self):
        entries = dp.read_entries(self.chain)
        evil = dict(entries[-1])
        evil["seq"] = len(entries)
        evil["prev"] = entries[-1]["hash"]
        evil["entry_id"] = "evil-mint"
        evil["kind"] = "MINT"
        evil["body"] = {"units": 10}
        evil.pop("hash", None)
        evil["hash"] = dp.entry_hash(evil)
        with self.assertRaises(K.MisfoldError):
            K.fold_kernel(entries + [evil])

    def test_supply_is_zero_and_unraisable(self):
        state, _ = self.k.state()
        self.assertEqual(state["supply_units"], 0)
        self.assertEqual(state["counts"].get("GENESIS"), 1)
        self.assertEqual(len(state["anchors"]), 1)  # GROUND-CONTROL import

    def test_unit_transfer_cannot_fold(self):
        with self.assertRaises(K.MisfoldError):
            self.k.apply({"entry_id": "xfer", "kind": "TRANSFER",
                          "actor": "w1-test",
                          "body": {"amount": 5, "to": "someone"},
                          "ts": ts(50)})
        # the refused transfer never landed: head unchanged
        state, _ = self.k.state()
        self.assertNotIn("xfer",
                         [e["entry_id"] for e in self.k.entries])

    # ---- the meter seam invents nothing ----

    def test_meter_is_modeled_and_empty(self):
        path = os.path.join(self._tmp.name, "meter.jsonl")
        k = build_chain(path)
        receipt = k.apply({"entry_id": "meter-check", "kind": "PLUS_ONE",
                           "actor": "w1-test", "body": {}, "ts": ts(50)})
        self.assertEqual(receipt["meter"]["grade"], "MODELED")
        self.assertIsNone(receipt["meter"]["joules"])

    # ---- no network in the kernel ----

    def test_kernel_has_no_network_io(self):
        import ast
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "kernel.py")
        with open(path) as f:
            tree = ast.parse(f.read())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        for bad in ("urllib", "socket", "requests", "http", "ftplib",
                    "smtplib"):
            self.assertNotIn(bad, imported,
                             f"kernel must not import {bad}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
