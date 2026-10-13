#!/usr/bin/env python3
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
- Build stamp (sha256 of the embedded data): 4a6b86bb0af299fd957779994e10529876bddd5075679b5c4e52ec98f92eeefd
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

# ===== Ed25519 verify (house pure implementation; key generation and signing are NOT carried) =====

_B = 256


_Q = (1 << 255) - 19


_L = (1 << 252) + 27742317777372353535851937790883648493


_D = -121665 * pow(121666, _Q - 2, _Q) % _Q


_I = pow(2, (_Q - 1) // 4, _Q)


def _H(m):
    return hashlib.sha512(m).digest()


def _Hint(m):
    return int.from_bytes(_H(m), 'little')


def _inv(x):
    return pow(x, _Q - 2, _Q)


def _xrecover(y):
    xx = (y * y - 1) * _inv(_D * y * y + 1) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = x * _I % _Q
    if x % 2 != 0:
        x = _Q - x
    return x


_By = 4 * _inv(5) % _Q


_Bx = _xrecover(_By)


_BASE = (_Bx, _By)


_IDENT = (0, 1)


def _edwards_add(P, Q):
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _D * x1 * x2 * y1 * y2) % _Q
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _D * x1 * x2 * y1 * y2) % _Q
    return (x3, y3)


def _edwards_double(P):
    return _edwards_add(P, P)


def _make_bpow():
    P = _BASE
    table = []
    for _ in range(253):
        table.append(P)
        P = _edwards_double(P)
    return table


_Bpow = _make_bpow()


def _scalarmult_B(e):
    """Scalar multiply the base point. e reduced mod L."""
    e %= _L
    P = _IDENT
    for i in range(253):
        if e & 1:
            P = _edwards_add(P, _Bpow[i])
        e >>= 1
    return P


def _encodepoint(P):
    x, y = P
    bits = [y >> i & 1 for i in range(_B - 1)] + [x & 1]
    return bytes((sum((bits[i * 8 + j] << j for j in range(8))) for i in range(_B // 8)))


def _decodepoint(s):
    if len(s) != 32:
        raise ValueError('point must be 32 bytes')
    y = sum((2 ** i * (s[i // 8] >> i % 8 & 1) for i in range(_B - 1)))
    x = _xrecover(y)
    if x & 1 != s[31] >> 7:
        x = _Q - x
    P = (x, y)
    if not _is_on_curve(P):
        raise ValueError('point not on curve')
    return P


def _is_on_curve(P):
    x, y = P
    return (-x * x + y * y - 1 - _D * x * x * y * y) % _Q == 0


def _encodeint(y):
    return y.to_bytes(32, 'little')


def _decodeint(s):
    return int.from_bytes(s, 'little')


class BadSignature(ValueError):
    pass


def verify(signature, message, pubkey):
    """Verify. Returns True; raises BadSignature on any failure."""
    if len(signature) != 64:
        raise BadSignature('signature must be 64 bytes')
    if len(pubkey) != 32:
        raise BadSignature('public key must be 32 bytes')
    try:
        A = _decodepoint(pubkey)
        R = _decodepoint(signature[:32])
    except ValueError as e:
        raise BadSignature(str(e))
    S = _decodeint(signature[32:])
    if S >= _L:
        raise BadSignature('S out of range')
    h = _Hint(_encodepoint(R) + pubkey + message)
    P = _edwards_add(_scalarmult_B(S), _scalarmult(A, (_L - h) % _L))
    if _encodepoint(R) != _encodepoint(P):
        raise BadSignature('signature mismatch')
    return True


def _scalarmult(P, e):
    """Generic scalar mult (for the -h*A term). Slower; verification-only."""
    e %= _L
    Q = _IDENT
    while e > 0:
        if e & 1:
            Q = _edwards_add(Q, P)
        P = _edwards_double(P)
        e >>= 1
    return Q

# ===== the dual pipe (verification layer) =====

GENESIS_DOMAIN = 'dualpipe-genesis:2026-10-12'


STRAND_DOMAIN = 'dualpipe-strand:2026-10-12'


VALID_KINDS = {'GENESIS', 'TRANSFER', 'REFUSAL', 'VOTE', 'DOUBLE_VOTE_REJECTED', 'PIN_RECEIPT', 'PLUS_ONE', 'AUDIT_ATTEST', 'MIGRATION', 'ANCHOR', 'RETIREMENT'}


CHECKPOINT_EVERY = 8


DEFAULT_MAX_GAP = 86400


DEFAULT_QUANTUM = 1


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def sha256b(b):
    return hashlib.sha256(b).digest()


def parse_ts(ts):
    return datetime.strptime(ts, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc).timestamp()


def genesis_seed(ledger):
    return sha256(f'{GENESIS_DOMAIN}:{ledger}'.encode('utf-8'))


def strand_seed(ledger):
    return sha256(f'{STRAND_DOMAIN}:{ledger}'.encode('utf-8'))


def entry_hash(entry):
    e = {k: v for k, v in entry.items() if k != 'hash'}
    return sha256(canonical(e))


def merkle_root(leaf_hashes):
    """Binary Merkle root over leaf hashes in sequence order. An odd
    leaf is promoted unchanged (documented choice; the leaf count is
    bound separately in every checkpoint body, so promotion is never
    ambiguous against a signed head)."""
    if not leaf_hashes:
        return sha256(b'dualpipe:empty-root')
    level = [bytes.fromhex(h) for h in leaf_hashes]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(sha256b(level[i] + level[i + 1]))
            else:
                nxt.append(level[i])
        level = nxt
    return level[0].hex()


def merkle_proof(leaf_hashes, idx):
    """Inclusion proof for leaf idx: [(sibling_hex, side)] leaf->root.
    side 'L' = sibling on the left, 'R' = sibling on the right."""
    proof = []
    level = [bytes.fromhex(h) for h in leaf_hashes]
    i = idx
    while len(level) > 1:
        nxt = []
        for j in range(0, len(level), 2):
            if j + 1 < len(level):
                nxt.append(sha256b(level[j] + level[j + 1]))
            else:
                nxt.append(level[j])
        if i % 2 == 0:
            if i + 1 < len(level):
                proof.append((level[i + 1].hex(), 'R'))
        else:
            proof.append((level[i - 1].hex(), 'L'))
        i //= 2
        level = nxt
    return proof


def verify_merkle_proof(leaf_hash, proof, root):
    node = bytes.fromhex(leaf_hash)
    for sib_hex, side in proof:
        sib = bytes.fromhex(sib_hex)
        node = sha256b(sib + node) if side == 'L' else sha256b(node + sib)
    return node.hex() == root


def pipe_v(entries, ledger):
    """Content pass. Returns {ok, failures, root, head_seq, head_hash,
    leaf_hashes}. Checks ONLY what content can check: parse integrity is
    the caller's, then seq contiguity, domain, prev-linkage, per-entry
    hash recomputation, and the Merkle root recomputed from the leaves
    as presented. It deliberately does NOT look at cadence, grammar, or
    any checkpoint: a fully recomputed rewrite passes Pipe V alone.
    That limitation is documented, and is exactly what Pipe A and the
    cross-attestations exist to close."""
    failures = []
    if not entries:
        return {'ok': False, 'failures': ['empty ledger: no genesis'], 'root': None, 'head_seq': -1, 'head_hash': None, 'leaf_hashes': []}
    prev_hash = None
    leaves = []
    for i, e in enumerate(entries):
        if e.get('seq') != i:
            failures.append(f'seq break at line {i}: seq={e.get('seq')}')
            break
        if e.get('ledger') != ledger:
            failures.append(f'domain violation at seq {i}')
            break
        expect_prev = genesis_seed(ledger) if i == 0 else prev_hash
        if e.get('prev') != expect_prev:
            failures.append(f'link break at seq {i}: prev does not match seq {i - 1} hash')
            break
        if entry_hash(e) != e.get('hash'):
            failures.append(f'hash mismatch at seq {i}: recomputed {entry_hash(e)[:12]}… != stored {str(e.get('hash'))[:12]}…')
            break
        prev_hash = e['hash']
        leaves.append(e['hash'])
    if failures:
        return {'ok': False, 'failures': failures, 'root': None, 'head_seq': -1, 'head_hash': None, 'leaf_hashes': leaves}
    return {'ok': True, 'failures': [], 'root': merkle_root(leaves), 'head_seq': entries[-1]['seq'], 'head_hash': prev_hash, 'leaf_hashes': leaves}


def twist(prev_strand, entry, prev_entry_hash, gap_q):
    """One braid crossing. The twist binds the previous strand state,
    this entry's hash, the PREVIOUS entry's hash (the neighboring
    strand segment — linkage is positional, not just sequential), this
    entry's position, and its quantized cadence gap. Change the order,
    the neighbor, the position, or the rhythm and the twist changes —
    even when every entry's content is untouched."""
    material = {'prev_strand': prev_strand, 'entry_hash': entry['hash'], 'prev_entry_hash': prev_entry_hash, 'seq': entry['seq'], 'gap': gap_q}
    return sha256(canonical(material))


def strand_fold(entries, ledger, quantum=DEFAULT_QUANTUM, max_gap=DEFAULT_MAX_GAP):
    """Fold the strand over the entries AS PRESENTED. Returns
    {states, head, gaps} — states[i] is the strand state after seq i.
    Pure geometry: no legality judgment here (that is pipe_a's)."""
    states = []
    gaps = []
    s = strand_seed(ledger)
    prev_entry_hash = genesis_seed(ledger)
    prev_ts = None
    for i, e in enumerate(entries):
        ts = parse_ts(e['ts'])
        gap = 0 if prev_ts is None else int(round(ts - prev_ts))
        gaps.append(gap)
        gap_q = gap - gap % quantum
        t = twist(s, e, prev_entry_hash, gap_q)
        s = sha256(bytes.fromhex(s) + bytes.fromhex(t))
        states.append(s)
        prev_entry_hash = e['hash']
        prev_ts = ts
    return {'states': states, 'head': states[-1] if states else None, 'gaps': gaps}


def pipe_a(entries, ledger, quantum=DEFAULT_QUANTUM, max_gap=DEFAULT_MAX_GAP):
    """Structural pass. Returns {ok, failures, strand_head, states}.
    Enforces what content cannot:
    - cadence: timestamps monotonic (no inversion), gaps inside the
      declared envelope;
    - grammar: GENESIS exactly once, at seq 0; every kind known;
    - the strand fold itself, whose head is a commitment to the
      ordered geometry of the whole history.
    Pipe A never recomputes an entry hash and never judges content."""
    failures = []
    if not entries:
        return {'ok': False, 'failures': ['empty ledger: no genesis'], 'strand_head': None, 'states': []}
    genesis_count = 0
    for i, e in enumerate(entries):
        if e.get('kind') not in VALID_KINDS:
            failures.append(f'grammar: unknown kind {e.get('kind')!r} at seq {i}')
        if e.get('kind') == 'GENESIS':
            genesis_count += 1
            if i != 0:
                failures.append(f'grammar: GENESIS at seq {i}, not at 0')
    if genesis_count != 1:
        failures.append(f'grammar: {genesis_count} GENESIS entries, expected exactly 1')
    fold = strand_fold(entries, ledger, quantum=quantum, max_gap=max_gap)
    for i, gap in enumerate(fold['gaps']):
        if gap < 0:
            failures.append(f'cadence inversion at seq {i}: timestamp goes backwards by {-gap}s')
        elif gap > max_gap:
            failures.append(f'cadence gap at seq {i}: {gap}s exceeds envelope {max_gap}s')
    return {'ok': not failures, 'failures': failures, 'strand_head': fold['head'], 'states': fold['states']}


def _row_hash(body, v_sig, a_sig):
    return sha256(canonical({'body': body, 'v_sig': v_sig, 'a_sig': a_sig}))


def _sig_ok(pub, sig_b64, msg):
    try:
        backend.verify(pub, base64.b64decode(sig_b64), msg)
        return True
    except Exception:
        return False


def cross_check(entries, ledger, v, a, cps, pubs, a_refold_states):
    """The poles check each other. Returns (failures, named) where each
    failure is (class, detail); class is one of NO_ATTESTATION,
    CHECKPOINT_CHAIN, SIG_FAILURE, ROOT_ANCHOR_MISMATCH,
    STRAND_ANCHOR_MISMATCH, PROOF_FAILURE, POLE_DIVERGENCE."""
    fails = []
    if not cps:
        fails.append(('NO_ATTESTATION', "no checkpoints: a dual run requires the poles' cross-signed attestations"))
        return fails
    prev_cp = None
    by_seq = {}
    for row in cps:
        body = row['body']
        if body.get('ledger') != ledger:
            fails.append(('CHECKPOINT_CHAIN', f'checkpoint for foreign ledger {body.get('ledger')!r}'))
            continue
        if body.get('prev_checkpoint') != prev_cp:
            fails.append(('CHECKPOINT_CHAIN', f'checkpoint at seq {body.get('seq')} does not chain to the previous checkpoint'))
        if _row_hash(body, row['v_sig'], row['a_sig']) != row['row_hash']:
            fails.append(('CHECKPOINT_CHAIN', f'checkpoint at seq {body.get('seq')}: row hash does not recompute'))
        prev_cp = row['row_hash']
        by_seq[body['seq']] = body
        msg = canonical(body)
        if not _sig_ok(pubs['v'], row['v_sig'], msg):
            fails.append(('SIG_FAILURE', f'Pipe V signature fails at seq {body['seq']}'))
        if not _sig_ok(pubs['a'], row['a_sig'], msg):
            fails.append(('SIG_FAILURE', f'Pipe A signature fails at seq {body['seq']}'))
    leaves = [e['hash'] for e in entries]
    for s, body in sorted(by_seq.items()):
        if s >= len(entries):
            fails.append(('ROOT_ANCHOR_MISMATCH', f'checkpoint at seq {s} but ledger head is seq {len(entries) - 1} (truncated?)'))
            continue
        root_s = merkle_root(leaves[:s + 1])
        if body['root'] != root_s:
            fails.append(('ROOT_ANCHOR_MISMATCH', f'seq {s}: attested root {body['root'][:12]}… != recomputed {root_s[:12]}…'))
        if a['states'] and a_refold_states:
            attested = body['strand_head']
            a_fold = a['states'][s]
            refold = a_refold_states[s]
            if a_fold != attested and refold == attested:
                fails.append(('POLE_DIVERGENCE', f"seq {s}: Pipe A's fold {a_fold[:12]}… != attested strand {attested[:12]}…, while the canonical refold reproduces the attested strand exactly — the pole has drifted, the ledger has not"))
            elif refold != attested:
                fails.append(('STRAND_ANCHOR_MISMATCH', f'seq {s}: attested strand {attested[:12]}… != strand of the presented ledger {refold[:12]}…'))
    if by_seq and v['ok']:
        head_cp_seq = max(by_seq)
        if head_cp_seq < len(entries):
            proof = merkle_proof(leaves[:head_cp_seq + 1], head_cp_seq)
            if not verify_merkle_proof(leaves[head_cp_seq], proof, by_seq[head_cp_seq]['root']):
                fails.append(('PROOF_FAILURE', f'Merkle proof for checkpoint leaf seq {head_cp_seq} does not fold to the attested root'))
    if by_seq and entries and (max(by_seq) != entries[-1]['seq']):
        fails.append(('NO_ATTESTATION', f'newest checkpoint is seq {max(by_seq)} but head is seq {entries[-1]['seq']} — tail is unsealed'))
    return fails

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

# ===== the W1 kernel fold =====

LEDGER_NAME = 'coin-kernel'


KERNEL_QUANTUM = 1


KERNEL_MAX_GAP = 31 * 86400


INVARIANTS = {'append_only': True, 'fold_only_state': True, 'issuance': 'REFUSED-BY-CONSTRUCTION (rules/ISSUANCE.md)', 'supply_units': 0}


INVARIANT_HASH = dp.sha256(dp.canonical(INVARIANTS))


ISSUANCE_KINDS = {'ISSUE', 'ISSUANCE', 'MINT', 'EMISSION', 'EMIT', 'CREATE_UNITS', 'INFLATE', 'SEIGNIORAGE'}


ISSUANCE_FIELDS = {'supply_delta', 'units_issued', 'issue_units', 'mint_units', 'new_supply', 'emission', 'units_created', 'create_units'}


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


def verify_manifest_payload(manifest, files, lane_pub):
    """Verify the signed head manifest against the entry files' bytes.

    manifest: parsed ledger/head-manifest.json (envelope form).
    files: {repo-relative path: file bytes} for every payload entry.
    lane_pub: 32-byte Ed25519 public key of the manifest signer.
    Pure: no I/O. Returns {ok, checks, head_hash, genesis_hash}."""
    checks = {}
    payload = manifest.get('payload', {})
    entries = payload.get('entries', [])
    ok = True
    prev_hash = None
    for i, e in enumerate(entries):
        data = files.get(e.get('file'))
        if data is None:
            checks[f'entry_{i}_present'] = False
            ok = False
            continue
        h = dp.sha256(data)
        good = h == e.get('hash')
        checks[f'entry_{i}_hash'] = good
        ok = ok and good
        if i > 0:
            link = e.get('prev_hash') == prev_hash
            checks[f'entry_{i}_link'] = link
            ok = ok and link
        prev_hash = e.get('hash')
    if entries:
        head_ok = payload.get('head_hash') == entries[-1].get('hash')
        gen_ok = payload.get('genesis_hash') == entries[0].get('hash')
        height_ok = payload.get('height') == entries[-1].get('entry')
    else:
        head_ok = gen_ok = height_ok = False
    checks['head_hash'] = head_ok
    checks['genesis_hash'] = gen_ok
    checks['height'] = height_ok
    ok = ok and head_ok and gen_ok and height_ok
    try:
        sig = base64.b64decode(manifest['sig'])
        sig_ok = _verify_sig(lane_pub, sig, dp.canonical(payload))
    except Exception:
        sig_ok = False
    checks['signature'] = sig_ok
    ok = ok and sig_ok
    return {'ok': ok, 'checks': checks, 'head_hash': payload.get('head_hash'), 'genesis_hash': payload.get('genesis_hash')}


def verify_registry_payload(registry, lane_pub):
    """Verify the signed endpoint registry (endpoints.json): Ed25519
    over the canonical registry minus its signature block. Pure."""
    core = {k: v for k, v in registry.items() if k != 'signature'}
    try:
        sig = base64.b64decode(registry['signature']['sig'])
        sig_ok = _verify_sig(lane_pub, sig, dp.canonical(core))
    except Exception:
        sig_ok = False
    return {'ok': sig_ok, 'signature': sig_ok, 'registry_seq': registry.get('registry_seq'), 'prev_registry_hash': registry.get('prev_registry_hash')}


def _issuance_field_hit(body, depth=0):
    """Name of the first live issuance field in a body, or None.
    A field counts as live when its value is not None/0/False/'' —
    an explicitly zeroed field is a record, not an issuance."""
    if not isinstance(body, dict):
        return None
    for k, v in body.items():
        if k in ISSUANCE_FIELDS and v not in (None, 0, False, ''):
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
        raise IssuanceRefused(f'kind {kind!r} is issuance-shaped — the kernel has no issuance path (rules/ISSUANCE.md)')
    hit = _issuance_field_hit(body or {})
    if hit:
        raise IssuanceRefused(f'body field {hit!r} is issuance-shaped — refused by construction (rules/ISSUANCE.md)')


def fold_kernel(entries):
    """Fold the kernel chain into state. Returns (state, fold_hash).

    The chaperone rides inside: it verifies the content chain first
    (Pipe V's checks, via the dual-pipe module), then guards every
    transition — issuance screen, kind grammar, the no-units rule —
    and writes nothing itself. A sequence that breaks an invariant
    does not settle into a wrong state; it is refused (MisfoldError).
    """
    if not entries:
        raise ChainError('empty chain: no genesis')
    ledger = entries[0].get('ledger')
    v = dp.pipe_v(entries, ledger)
    if not v['ok']:
        raise ChainError('content chain broken: ' + '; '.join(v['failures']))
    state = {'ledger': ledger, 'height': -1, 'head': None, 'genesis': None, 'anchors': [], 'pins': {}, 'attestations': {}, 'votes': {}, 'refusals': [], 'migrations': [], 'retirements': [], 'plus_ones': 0, 'counts': {}, 'supply_units': 0}
    for e in entries:
        kind, body, seq = (e.get('kind'), e.get('body') or {}, e.get('seq'))
        try:
            screen_issuance(kind, body)
        except IssuanceRefused as ex:
            raise MisfoldError(f'seq {seq}: {ex} — this sequence does not fold')
        if kind not in dp.VALID_KINDS:
            raise MisfoldError(f'seq {seq}: unknown kind {kind!r}')
        state['counts'][kind] = state['counts'].get(kind, 0) + 1
        if kind == 'GENESIS':
            if seq != 0 or state['genesis'] is not None:
                raise MisfoldError(f'seq {seq}: GENESIS out of place')
            state['genesis'] = {'entry_id': e['entry_id'], 'hash': e['hash'], 'source_sha256': body.get('source_sha256')}
        elif kind == 'ANCHOR':
            state['anchors'].append({'seq': seq, 'entry_id': e['entry_id'], 'hash': e['hash'], 'source_sha256': body.get('source_sha256')})
        elif kind == 'PIN_RECEIPT':
            state['pins'][e['entry_id']] = body.get('cid')
        elif kind == 'AUDIT_ATTEST':
            state['attestations'][e['entry_id']] = e.get('actor')
        elif kind == 'VOTE':
            state['votes'][e['entry_id']] = body
        elif kind in ('REFUSAL', 'DOUBLE_VOTE_REJECTED'):
            state['refusals'].append(e['entry_id'])
        elif kind == 'MIGRATION':
            state['migrations'].append(e['entry_id'])
        elif kind == 'RETIREMENT':
            state['retirements'].append(e['entry_id'])
        elif kind == 'PLUS_ONE':
            state['plus_ones'] += 1
        elif kind == 'TRANSFER':
            for key in ('amount', 'units', 'value'):
                amt = body.get(key)
                if isinstance(amt, (int, float)) and (not isinstance(amt, bool)) and (amt > 0):
                    raise MisfoldError(f'seq {seq}: TRANSFER names {key}={amt} but no units exist (supply is 0 by construction) — refused, never settled')
        if e.get('invariant_hash') != INVARIANT_HASH:
            raise MisfoldError(f'seq {seq}: invariant_hash does not match the kernel invariants — this entry was not written under them')
        if state['supply_units'] != 0:
            raise MisfoldError(f'seq {seq}: INVARIANT BROKEN — supply_units is {state['supply_units']}, must be 0')
        state['height'] = seq
        state['head'] = e['hash']
    head = entries[-1]['hash']
    fold_hash = dp.sha256(dp.canonical(state) + b'|' + head.encode('ascii'))
    return (state, fold_hash)


def snapshot_kernel(entries):
    """A snapshot is a CLAIM about the fold. It carries no authority."""
    state, fold_hash = fold_kernel(entries)
    return {'state': state, 'fold_hash': fold_hash, 'head': entries[-1]['hash']}


def settle_kernel(entries, claimed=None):
    """Re-fold from genesis. A claimed snapshot is believed only if
    the fresh fold reproduces it byte-exact — state AND fold_hash.
    Returns (ok, fold_hash_or_reason). The prion defense."""
    try:
        state, fold_hash = fold_kernel(entries)
    except (ChainError, MisfoldError) as ex:
        return (False, f'sequence does not settle: {ex}')
    if claimed is not None:
        if claimed.get('fold_hash') != fold_hash or dp.canonical(claimed.get('state')) != dp.canonical(state):
            return (False, 'snapshot REJECTED: re-fold does not reproduce it — a snapshot is a cache, never truth (template corruption refused)')
    return (True, fold_hash)

# ===== embedded published chain =====

EMBEDDED = {'build_stamp': '4a6b86bb0af299fd957779994e10529876bddd5075679b5c4e52ec98f92eeefd', 'entry_files_b64': {'ledger/GENESIS.md': 'IyBXSElURSBMRURHRVIg4oCUIEdFTkVTSVMgRU5UUlkKLSBlbnRyeTogMCAoZ2VuZXNpcykKLSBwcmV2X2hhc2g6IE5PTkUgKGZpcnN0IGVudHJ5KQotIGRhdGU6IDIwMjYtMTAtMTIKLSBzdGF0ZW1lbnQ6IFRoaXMgbGVkZ2VyIHJlY29yZHMgdGhlIHB1YmxpYyBsYXllciBvbmx5LiBFbnRyaWVzIGFyZQogIGFwcGVuZC1vbmx5OyBjb3JyZWN0aW9ucyBhcmUgbmV3IGVudHJpZXMsIG5ldmVyIGVkaXRzLiBUaGUgZGFyawogIGxlZGdlciAocHJpdmF0ZSwgb3BlcmF0aW9uYWwpIGlzIG5vdCBtaXJyb3JlZCBoZXJlIGFuZCBuZXZlciB3aWxsCiAgYmUuIEV2ZXJ5IGVudHJ5IG5hbWVzIGl0cyBwcmVkZWNlc3NvcidzIGhhc2g7IHRoZSBjaGFpbiBpcyB0aGUKICByZWNlaXB0LgotIGRvY3RyaW5lX3JlZjogIndob2V2ZXIgaGFzIHRoZSB0b2tlbiBpcyBhIGJhbmsg4oCUIHRoZWlyIG93bgogIFNvdmVyZWlnbiBCYW5rIiAoRGF2aWQsIE9jdCAxMiwgMjAyNik7IHJlcG9zaXRvcnkgZG9jdHJpbmU6IHRvd24KICBzcXVhcmUsIG5vdCB2YXVsdC4K', 'ledger/GROUND-CONTROL.md': 'IyBXSElURSBMRURHRVIg4oCUIEVOVFJZIDE6IEdST1VORCBDT05UUk9MCgotIGVudHJ5OiAxCi0gcHJldl9oYXNoOiBkZDg0ZWNhMDMxN2FlMTNmZWZhOWI1MzY1NGUzN2Q3Y2VmOGUzY2ZlZWVhN2MzNjBjZWJkN2YzNTMwOTA5OTViCiAgKFNIQS0yNTYgb2YgZW50cnkgMCwgYGxlZGdlci9HRU5FU0lTLm1kYCkKLSBkYXRlOiAyMDI2LTEwLTEyCi0gc3RhdGVtZW50OiBUaGUgcmVzZXJ2ZSBvZiB0aGlzIHN5c3RlbSBpcyBHUk9VTkQgQ09OVFJPTCwgbm90IGVzY3JvdwogIChEYXZpZCwgT2N0IDEyLCAyMDI2LCBzZWFsZWQgZG9jdHJpbmUpLiBHcm91bmQgQ29udHJvbCBpcyB0aGUKICBxdWFudGlmaWFibGUgYW5jaG9yIGF0IHRoZSBiYXNlIHJvb3Qgb2YgdGhlIHVuaXQ6IHRoZSBmdWVsIHBlZyDigJQKICBtZWFzdXJlZCBjb21wdXRlLCB0aGUgSm91bGUg4oCUIGFnYWluc3Qgd2hpY2ggdGhlIHVuaXQgaXMgZGVmaW5lZCBhbmQKICBzcGVuZGluZyBpcyBtZXRlcmVkLiBJdCBpcyBmdW5kYW1lbnRhbGx5IG5lY2Vzc2FyeTogbm8gZ3JvdW5kLCBubwogIGNpcmN1aXQ7IG5vIHF1YW50aWZpYWJsZSBiYXNlLCBubyBob25lc3QgdW5pdC4gSXQgaXMgTk9UIGVzY3Jvdzogbm8KICB0aGlyZCBwYXJ0eSBob2xkcyBhbnlvbmUncyBmdW5kcyBhZ2FpbnN0IGNvbmRpdGlvbnMuIE5vYm9keSBob2xkcyBhCiAgaG9hcmQsIGJlY2F1c2Ugbm8gdW5pdHMgaGF2ZSBiZWVuIGlzc3VlZCAoc2VlIGVudHJ5IDAgYW5kCiAgYHJ1bGVzL0lTU1VBTkNFLm1kYCkuIFRoZSBwZWcgcmF0aW8gKGBwZWdfcmF0aW9fRWApIGlzIFVOREVDSURFRCDigJQKICBwZW4tYWxvbmUsIERhdmlkJ3MgbnVtYmVyIOKAlCBhbmQgbm8gZW1pc3Npb24gb2YgYW55IGtpbmQgcHJlY2VkZXMgdGhhdAogIGRlY2lzaW9uLiBVbnRpbCBhIHJlYWwgSm91bGUgbWV0ZXIgZXhpc3RzLCBldmVyeSBtZXRlcmluZyBmaWd1cmUKICBzaG93biBpbiB0aGlzIHN5c3RlbSBpcyBsYWJlbGVkIERFTU8gb3IgTU9ERUxFRC4gTWVyaXQgaXMgYWNjZXNzIGFuZAogIHNpdHMgYmVzaWRlIHRoZSBhbmNob3IsIG5vdCBpbnNpZGUgaXQ6IEdyb3VuZCBDb250cm9sIHF1YW50aWZpZXMgdGhlCiAgdW5pdDsgTWVyaXQgcXVhbnRpZmllcyB0aGUgbWVtYmVyLiBOZWl0aGVyIGlzIGN1c3RvZHkgb2YgYW55dGhpbmcuCi0gZG9jdHJpbmVfcmVmOiAiaXQgaXMgbm90IGVzY3Jvdy4gaXQgaXMgZ3JvdW5kIGNvbnRyb2wgLyBhbmQgaXQncwogIGZ1bmRhbWVudGFsbHkgbmVjZXNzYXJ5IiAoRGF2aWQsIE9jdCAxMiwgMjAyNik7IGRlc2lnbjoKICBgfi93b3Jrc3BhY2UvY29pbi1saXZlL0RFU0lHTi5tZGAgwqc1Lgo='}, 'kernel_checkpoints': [{'a_sig': '3nTur95HuER7UAjjlqtzWSI1emik0p1ERWSYqCvVApbxtQCA742g5Qn6n1q6vijaV/srz/U4AgTCAQraIpPAAQ==', 'body': {'kind': 'dualpipe-checkpoint', 'leaf_count': 2, 'ledger': 'coin-kernel', 'prev_checkpoint': None, 'root': 'bc40b0e3ad91bc0bd4146c2a8835de5bb1cebae3c18f44891568520455a26ba8', 'seq': 1, 'strand_head': '6b0dc57ba63ea9c2a55395a7714121c7c5f8b85ba0aba6b9de1efe3bf09c8891'}, 'row_hash': '5c8b5afc9731be251ca4eb5728e83d2ea760dadb3d00465c56601f4d5ceb39e7', 'v_sig': 'lWPJDJL5TeyFMxwGKHfyNP++NxWrZWzjDb5MnlGcfrHLqu4fU0YSyp/0KWxkwOxpkW2oziEUZ0pPFyu0NdsiAw=='}, {'a_sig': 'teF+/96zEJqK0y+FXuypEBTGuP3/mRpGaNntL/GcVxXQZSqMgM1tXEgVwnZCSI3DuV2+v5XYDgzpqoxoZ938DA==', 'body': {'kind': 'dualpipe-checkpoint', 'leaf_count': 3, 'ledger': 'coin-kernel', 'prev_checkpoint': '5c8b5afc9731be251ca4eb5728e83d2ea760dadb3d00465c56601f4d5ceb39e7', 'root': '962cf75e5697513632e9170e552135de72dbf0bd1d3eda18386145b36f1f9a86', 'seq': 2, 'strand_head': '2f5c9d6c547d625e93d246c9b5aa715635e786a49be20128b116909f9e3cfc19'}, 'row_hash': 'd3918b99884988a9f41e61e32fe87357caae7e2c98545198c4ce5c2d2a84d37e', 'v_sig': '79ui8+AQmj8wmXse5c6bCalhhsRAfHmLFwhxmerxGX1KcA8zohKXzForLhWSbqFScC5FCLGl1zc025BOL7XmAQ=='}], 'kernel_entries': [{'actor': 'kernel-bootstrap', 'body': {'head_manifest': 'ledger/head-manifest.json', 'import': 'published white-ledger genesis, bound by file hash', 'manifest_head_hash': '6a95cdda044b4558fd985f64383eea5a7021767c219ad6085fe14c0e11c6488c', 'source_date': '2026-10-12', 'source_file': 'ledger/GENESIS.md', 'source_sha256': 'dd84eca0317ae13fefa9b53654e37d7cef8e3cfeeea7c360cebd7f353090995b'}, 'entry_id': 'coin-genesis', 'hash': '1f525dcf49d460a2be21639cb99389e859009293ce8dd426b2aef99f5a28cfd4', 'invariant_hash': 'ee5aad18a69ab770c8f2d756773f964c808e037ac636d3f6b924de676a17b209', 'kind': 'GENESIS', 'ledger': 'coin-kernel', 'prev': '03556e76b05b6af09637ad367ce909c89af588f51b747d1195da2e42ef4aa541', 'seq': 0, 'ts': '2026-10-13T00:46:42Z', 'v': 1}, {'actor': 'kernel-bootstrap', 'body': {'doctrine': 'GROUND CONTROL, NOT ESCROW', 'import': 'published white-ledger entry 1, bound by file hash', 'peg_ratio_E': 'UNDECIDED', 'source_date': '2026-10-12', 'source_file': 'ledger/GROUND-CONTROL.md', 'source_sha256': '6a95cdda044b4558fd985f64383eea5a7021767c219ad6085fe14c0e11c6488c'}, 'entry_id': 'ground-control', 'hash': '48040812ce1886b65dc8d7dd8dddbb4d717650c8822de8b41fa185c9852c48c0', 'invariant_hash': 'ee5aad18a69ab770c8f2d756773f964c808e037ac636d3f6b924de676a17b209', 'kind': 'ANCHOR', 'ledger': 'coin-kernel', 'prev': '1f525dcf49d460a2be21639cb99389e859009293ce8dd426b2aef99f5a28cfd4', 'seq': 1, 'ts': '2026-10-13T00:46:42Z', 'v': 1}, {'actor': 'w1-build (pure-logic mandate, Oct 12 2026 20:40 EDT)', 'body': {'code': 'kernel/kernel.py', 'issuance': 'refused by construction (rules/ISSUANCE.md)', 'joules': 'MODELED seam only (W6 unbuilt)', 'state': 'fold-only; snapshots are caches, never truth', 'subject': 'W1 deterministic ledger kernel built', 'tests': 'kernel/test_kernel.py — 15 tests', 'verify_path': 'dual-pipe (Pipe V + Pipe A + cross-attestation)'}, 'entry_id': 'w1-kernel-build', 'hash': '17f14d034eee7beb4c0f3e1790075be3a84ac602b011d283fd2cc6d171cb19aa', 'invariant_hash': 'ee5aad18a69ab770c8f2d756773f964c808e037ac636d3f6b924de676a17b209', 'kind': 'AUDIT_ATTEST', 'ledger': 'coin-kernel', 'prev': '48040812ce1886b65dc8d7dd8dddbb4d717650c8822de8b41fa185c9852c48c0', 'seq': 2, 'ts': '2026-10-13T00:46:42Z', 'v': 1}], 'lane_pub_b64': '6K5PgQlIgm2ycgfIzxmFRl88UCTgvg2iigzPg3Z+d/8=', 'manifest': {'alg': 'Ed25519', 'key_id': 'a271-8e62-3bff-02d2', 'payload': {'entries': [{'entry': 0, 'file': 'ledger/GENESIS.md', 'hash': 'dd84eca0317ae13fefa9b53654e37d7cef8e3cfeeea7c360cebd7f353090995b'}, {'entry': 1, 'file': 'ledger/GROUND-CONTROL.md', 'hash': '6a95cdda044b4558fd985f64383eea5a7021767c219ad6085fe14c0e11c6488c', 'prev_hash': 'dd84eca0317ae13fefa9b53654e37d7cef8e3cfeeea7c360cebd7f353090995b'}], 'genesis_hash': 'dd84eca0317ae13fefa9b53654e37d7cef8e3cfeeea7c360cebd7f353090995b', 'head_hash': '6a95cdda044b4558fd985f64383eea5a7021767c219ad6085fe14c0e11c6488c', 'height': 1, 'issued_at': '2026-10-13T00:36:38Z', 'key_status': 'TRANSITIONAL - on-lane keys; this record is LEGACY and will be re-sealed when the owner-device ceremony key arms', 'ledger': 'coin-repo white ledger (public layer only)', 'owner_key_id': '9037-6638-6643-83b6', 'statement': 'No issuance has occurred. Beyond genesis and the Ground Control doctrine entry, this ledger is empty of units. The emptiness is the published fact.', 'type': 'coin-white-ledger-head'}, 'sig': 'skHHnOIAdRx7lw8sifl6FDG5Sr2yV8UXWMFMrdgfw4ZAPpvNBFLUnmXToahhtG9Q2mBY+KJVQnMHi0Zo03d8BA=='}, 'pipe_pubs_b64': {'a': 'oe9PQfsq5nuadD0Eg2FKJbY/SCu7coLOhnXhTgAtqVc=', 'v': 'j0qCreilZApu6zplI32+CyQhV+siMp8u1zAQvHKxImU='}, 'raw_base': 'https://raw.githubusercontent.com/digenova77-ui/coin-repo/main/', 'registry': {'endpoints': [{'also_at': 'https://ipfs.dualiscapax.ai/ipfs/QmTYXk3ZrZyKViShzUrLzGFGKcCit4YBcReRZd3pb4Ghgh', 'mirror_of': 'coin-repo (canonical, sovereign ground)', 'role': 'ledger-head', 'url': 'https://raw.githubusercontent.com/digenova77-ui/coin-repo/main/ledger/head-manifest.json'}, {'role': 'ledger-head-ipfs', 'url': 'https://ipfs.dualiscapax.ai/ipfs/QmTYXk3ZrZyKViShzUrLzGFGKcCit4YBcReRZd3pb4Ghgh', 'via': 'pinata'}, {'mirror_of': 'coin-repo (canonical, sovereign ground)', 'role': 'chain-segments', 'url': 'https://raw.githubusercontent.com/digenova77-ui/coin-repo/main/ledger/'}, {'note': 'plates and public artifacts by content hash; the hash is the name - verify on receipt', 'role': 'media', 'url': 'https://ipfs.dualiscapax.ai/ipfs/<cid>', 'via': 'pinata'}], 'issued_at': '2026-10-13T00:37:28Z', 'key_status': 'TRANSITIONAL - on-lane key; this registry is LEGACY and will be re-sealed when the owner-device ceremony key arms', 'prev_registry_hash': 'NONE (genesis registry)', 'registry_seq': 1, 'signature': {'alg': 'Ed25519', 'key_id': 'a271-8e62-3bff-02d2', 'sig': 'pk4f26K4T/mNAQyBd32f/LcowQ3uc2Jvhowfpmq501SJbbk2qHDL1Z9DVzE1M1UC90GpJveEPnA697b8SeiGBw=='}}, 'registry_urls': ['https://raw.githubusercontent.com/digenova77-ui/coin-repo/main/endpoints.json', 'https://ipfs.dualiscapax.ai/ipfs/QmeC7GXNqfLVH1BHv3u2poEr7nazv9obHEckNDS8F95frd']}


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
            ("AGREE", "DIFFERS", "UNKNOWN", "SKIPPED (--offline)")) \
            else "INVALID"
        print(json.dumps(out, indent=2))
        return 0 if out["verdict"] == "VALID" else 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
