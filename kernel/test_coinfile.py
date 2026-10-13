#!/usr/bin/env python3
"""Tests for the W8 coin-file (coin.py, assembled by
tools/build_coinfile.py).

Proven here:
- the build is BYTE-DETERMINISTIC: two builds of the same inputs
  produce the identical file (sha256 compared);
- the shipped coin.py verifies its embedded chain offline: manifest
  signature, registry signature, dual pipe, and the fold settle;
- AGREEMENT: on a tampered chain, the coin-file's dual verdict and
  dualpipe.verify's verdict agree (both reject, same divergence
  family) — the assembled file carries the same verification code,
  and this test is where that claim is cashed;
- the coin-file folds the same state as the kernel (same fold hash).

Run: python3 -m unittest test_coinfile -v  (from ~/workspace/coin-repo/kernel)
"""
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.expanduser("~/workspace/dual-pipe"))
import dualpipe as dp  # noqa: E402
import kernel as K  # noqa: E402

BUILDER = os.path.join(REPO, "tools", "build_coinfile.py")
COIN = os.path.join(REPO, "coin.py")


def sha256_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def build(out, chain=None):
    cmd = [sys.executable, BUILDER, "--out", out]
    if chain:
        cmd += ["--chain", chain]
    subprocess.run(cmd, check=True, capture_output=True, text=True)
    return out


def load_coin(path):
    spec = importlib.util.spec_from_file_location("coinfile", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class CoinFileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.coin_b = os.path.join(cls._tmp.name, "coin-b.py")
        build(cls.coin_b)
        cls.coin = load_coin(COIN)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_build_is_byte_deterministic(self):
        self.assertEqual(sha256_file(COIN), sha256_file(self.coin_b))

    def test_shipped_coin_verifies_offline(self):
        r = subprocess.run([sys.executable, COIN, "verify", "--offline"],
                           capture_output=True, text=True, timeout=300)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        out = json.loads(r.stdout)
        self.assertEqual(out["verdict"], "VALID")
        self.assertTrue(out["local"]["manifest"]["checks"]["signature"])
        self.assertTrue(out["local"]["registry"]["signature"])
        self.assertTrue(out["local"]["dual"]["ok"])

    def test_coin_fold_matches_kernel_fold(self):
        st_coin, fh_coin = self.coin.fold_kernel(
            self.coin.EMBEDDED["kernel_entries"])
        k = K.Kernel(os.path.join(REPO, "kernel", "chain.jsonl"))
        _st, fh_kernel = k.state()
        self.assertEqual(fh_coin, fh_kernel)

    def test_tampered_chain_both_verifiers_reject(self):
        # substitute an entry body, recompute the whole chain so
        # content-only checks pass — the class the dual pipe exists
        # to catch. dualpipe.verify rejects it against the committed
        # checkpoints; a coin-file built over the tampered chain,
        # still carrying the honest checkpoints, must reject it too.
        entries = dp.read_entries(os.path.join(REPO, "kernel",
                                               "chain.jsonl"))
        entries[2]["body"] = dict(entries[2]["body"])
        entries[2]["body"]["subject"] = "forged subject"
        out = []
        prev = dp.genesis_seed(entries[0]["ledger"])
        for e in entries:
            e = dict(e)
            e["prev"] = prev
            e.pop("hash", None)
            e["hash"] = dp.entry_hash(e)
            out.append(e)
            prev = e["hash"]
        tampered = os.path.join(self._tmp.name, "tampered.jsonl")
        dp.write_entries(tampered, out)
        with open(dp.checkpoints_path(os.path.join(
                REPO, "kernel", "chain.jsonl"))) as f:
            cps = f.read()
        with open(dp.checkpoints_path(tampered), "w") as f:
            f.write(cps)
        ref = dp.verify(tampered, mode="dual",
                        a_quantum=K.KERNEL_QUANTUM,
                        a_max_gap=K.KERNEL_MAX_GAP)
        self.assertFalse(ref["ok"])
        evil_coin = os.path.join(self._tmp.name, "coin-evil.py")
        build(evil_coin, chain=tampered)
        mod = load_coin(evil_coin)
        local = mod.local_verdicts()
        self.assertFalse(local["dual"]["ok"])
        self.assertEqual(local["dual"]["divergence"], ref["divergence"])
        self.assertFalse(local["ok"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
