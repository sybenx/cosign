#!/usr/bin/env python3
"""Generate Keykin Core test vectors (core.md draft 8.1, §14).

Pure Python, no dependencies. Run: python3 -I gen_vectors.py > vectors.json
Every value is derived from fixed inputs, so the output is reproducible. FROST signing rounds
themselves are not here: they come from frost-secp256k1-tr's own vectors plus the cases in vectors.md.
"""
import hashlib, json, base64

# --- secp256k1 -------------------------------------------------------------------------------
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

def add(a, b):
    if a is None: return b
    if b is None: return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0: return None
    if a == b: l = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else: l = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (l * l - a[0] - b[0]) % P
    return (x, (l * (a[0] - x) - a[1]) % P)

def mul(k, pt=G):
    k %= N; r = None
    while k:
        if k & 1: r = add(r, pt)
        pt = add(pt, pt); k >>= 1
    return r

def neg(pt): return None if pt is None else (pt[0], (-pt[1]) % P)
def comp(pt): return ("02" if pt[1] % 2 == 0 else "03") + "%064x" % pt[0]
def xonly(pt): return "%064x" % pt[0]
def sha(*parts): return hashlib.sha256(b"".join(parts)).digest()
def hx(b): return b.hex()
def i32(i): return i.to_bytes(4, "big")
def sc(k): return (k % N).to_bytes(32, "big")
def cb(pt): return bytes.fromhex(comp(pt))
def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def jcs(o): return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def priv_from(label):  # deterministic test keys, even-y public
    k = int.from_bytes(sha(b"keykin-test/" + label.encode()), "big") % N
    pt = mul(k)
    if pt[1] % 2: k = N - k; pt = mul(k)
    return k, pt

out = {"spec": "Keykin Core draft 8.1", "note": "hex unless stated; x-only keys are 32 bytes", "cases": {}}
C = out["cases"]

g_sk, g_pt = priv_from("group")      # stands in for the group point; nobody holds g_sk in real life
g = bytes.fromhex(xonly(g_pt))
m = bytes.fromhex(xonly(priv_from("inviter")[1]))
n = bytes.fromhex(xonly(priv_from("newdevice")[1]))
s = sha(b"s")[:16]; t = sha(b"t")[:16]
epoch_id = sha(b"epoch")[:16]

# 1. join check (§4.1)
def six(d): return "%06d" % (int.from_bytes(d[:8], "big") % 10**6)
C["join_check"] = [{"g": hx(g), "m": hx(m), "n": hx(n), "s": hx(s), "t": hx(t),
                    "code": six(sha(b"keykin-join/1", g, m, n, s, t))},
                   {"note": "changing t changes the code", "g": hx(g), "m": hx(m), "n": hx(n), "s": hx(s),
                    "t": hx(sha(b"t2")[:16]), "code": six(sha(b"keykin-join/1", g, m, n, s, sha(b"t2")[:16]))}]

# 2. change hash, pair code (§3.2, §6.2)
change = {"add": {"key": hx(n), "kind": "device", "lock": None, "salt": 0}}
ch = sha(jcs(change))
r = sha(b"r")[:16]
C["change_hash"] = {"change": change, "jcs": jcs(change).decode(), "sha256": hx(ch)}
C["pair_code"] = {"g": hx(g), "change_hash": hx(ch), "r": hx(r), "code": six(sha(b"keykin-pair/1", g, ch, r))}

# 3. indices (§3.2)
def indices(key, salt):
    return [2**16 + int.from_bytes(sha(b"keykin-index/1", g, epoch_id, key, i32(salt), i32(j))[:4], "big") % 2**30
            for j in range(3)]
idx = indices(n, 0)
C["indices"] = {"g": hx(g), "epoch_id": hx(epoch_id), "key": hx(n), "salt": 0,
                "salt_encoding": "4-byte big-endian", "j_encoding": "4-byte big-endian",
                "indices": idx, "identifiers_32byte": [hx(sc(i)) for i in idx]}

# 4. wait ids and lock challenges (§6.1, §6.3)
event_id = sha(b"event")
backup_key = bytes.fromhex(xonly(priv_from("backup")[1]))
rr = sha(b"recovery-r")[:16]
hold_id = sha(b"hold", event_id)
rec_id = sha(b"recovery", backup_key, epoch_id, rr)
C["wait_ids"] = {"event_id": hx(event_id), "hold": hx(hold_id),
                 "backup_key": hx(backup_key), "epoch_id": hx(epoch_id), "r": hx(rr), "recovery": hx(rec_id)}
def chal(what): return b64u(sha(b"keykin-lock/1", g, what))
C["lock_challenge"] = [
    {"what": "sign ‖ event id", "challenge": chal(b"sign" + event_id)},
    {"what": "change ‖ change hash ‖ epoch id", "challenge": chal(b"change" + ch + epoch_id)},
    {"what": "cancel ‖ wait id", "challenge": chal(b"cancel" + rec_id)},
]
start, end = 1793600000, 1793600000 + 3 * 86400
C["waited_statement_digest"] = {"kind": "recovery", "wait": hx(rec_id), "start": start, "end": end,
    "digest": hx(sha(b"keykin-waited/1", g, b"recovery", rec_id, start.to_bytes(8, "big"), end.to_bytes(8, "big"))),
    "note": "start and end as 8-byte big-endian unix seconds"}

# 5. commitment rebuild from a device's own points (§3.4 step 4)
coeffs = [int.from_bytes(sha(b"coef", bytes([k])), "big") % N for k in range(4)]
if mul(coeffs[0])[1] % 2: coeffs = [N - a for a in coeffs]           # even-y group point
def f(x): return sum(a * pow(x, k, N) for k, a in enumerate(coeffs)) % N
commit = [mul(a) for a in coeffs]
def P_i(i, cm): 
    acc = None
    for k, ck in enumerate(cm): acc = add(acc, mul(pow(i, k, N), ck))
    return acc
dev = [1, 2, 3]
# rebuild: points at x = 0 (C0) and the device's indices determine a_k·G via Lagrange basis coefficients
xs = [0] + dev
ys = [commit[0]] + [mul(f(i)) for i in dev]
def poly_mul(a, b):
    r = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        for j, y in enumerate(b): r[i + j] = (r[i + j] + x * y) % N
    return r
rebuilt = [None] * 4
for j, xj in enumerate(xs):
    basis = [1]; den = 1
    for k, xk in enumerate(xs):
        if k != j: basis = poly_mul(basis, [(-xk) % N, 1]); den = den * (xj - xk) % N
    inv = pow(den, -1, N)
    for k in range(4): rebuilt[k] = add(rebuilt[k], mul(basis[k] * inv % N, ys[j]))
assert [comp(p) for p in rebuilt] == [comp(p) for p in commit]
tampered = list(commit); tampered[2] = add(tampered[2], G)
C["commitment_rebuild"] = {
    "commitment": [comp(p) for p in commit],
    "device_indices": dev, "device_points": [comp(mul(f(i))) for i in dev],
    "rebuilt": [comp(p) for p in rebuilt], "valid": True,
    "negative": {"commitment": [comp(p) for p in tampered], "valid": False,
                 "note": "C2 changed by +G: the rebuild from the device's own points differs, so refuse"},
    "derived_points": {str(i): comp(P_i(i, commit)) for i in [4, 5, 6, idx[0]]},
}

# 6. weighted ECDH with DLEQ (§5.5)
q_sk = int.from_bytes(sha(b"peer"), "big") % N; Q = mul(q_sk)
signers = [1, 2, 3, 4]; i = 4; s_i = f(i)
lam = 1
for j in signers:
    if j != i: lam = lam * j * pow(j - i, -1, N) % N
Y = mul(lam * s_i, Q); W = mul(lam, P_i(i, commit))
k = int.from_bytes(sha(b"fixed-k-for-vectors"), "big") % N      # real k is hedged, §5.5
R1 = mul(k); R2 = mul(k, Q)
e = int.from_bytes(sha(b"keykin/ecdh-dleq/1", g, epoch_id, i32(i), cb(W), cb(Q), cb(Y), cb(R1), cb(R2)), "big") % N
z = (k + e * lam * s_i) % N
assert mul(z) == add(R1, mul(e, W)) and mul(z, Q) == add(R2, mul(e, Y))
total = None
for j in signers:
    lj = 1
    for jj in signers:
        if jj != j: lj = lj * jj * pow(jj - j, -1, N) % N
    total = add(total, mul(lj * f(j), Q))
assert total == mul(coeffs[0], Q)
C["ecdh_dleq"] = {"g": hx(g), "epoch_id": hx(epoch_id), "Q": comp(Q), "signers": signers, "i": i,
    "lambda_i": hx(sc(lam)), "Y": comp(Y), "W_i": comp(W), "k": hx(sc(k)), "R1": comp(R1), "R2": comp(R2),
    "e": hx(sc(e)), "z": hx(sc(z)), "valid": True,
    "negative": [{"case": "z + 1", "z": hx(sc(z + 1)), "valid": False},
                 {"case": "answer covers indices [4, 4]", "valid": False},
                 {"case": "Q is the identity", "valid": False}]}

# 7. policy tables (no crypto) -----------------------------------------------------------------
C["future_dates"] = [
    {"kind": 1, "ahead_s": 86400, "accept": True}, {"kind": 0, "ahead_s": 601, "accept": False},
    {"kind": 3, "ahead_s": 599, "accept": True}, {"kind": 10002, "ahead_s": 3600, "accept": False},
    {"kind": 30023, "ahead_s": 700, "accept": False}, {"kind": 30023, "ahead_s": 60, "accept": True}]
C["stateless_destructive"] = [
    {"event": {"kind": 62}, "needs": "approval or hold"},
    {"event": {"kind": 5, "targets": 1}, "needs": "nothing"},
    {"event": {"kind": 5, "targets": 5}, "needs": "approval or hold"},
    {"event": {"kind": 5, "targets": 2, "unapproved_targets_last_10min": 4}, "needs": "approval or hold"},
    {"event": {"kind": 0, "content": "{}"}, "needs": "approval or hold"},
    {"event": {"kind": 0, "content": "{\"name\":\"x\"}"}, "needs": "nothing"},
    {"event": {"kind": 3, "tags": []}, "needs": "approval or hold"},
    {"event": {"kind": 3, "tags": [["p", "…"]]}, "needs": "nothing"},
    {"event": {"kind": 10002, "tags": []}, "needs": "approval or hold"}]
C["lifetimes"] = [
    {"type": "sign", "cls": "sign", "age_s": 89, "accept": True}, {"type": "sign", "cls": "sign", "age_s": 91, "accept": False},
    {"type": "sign", "cls": "ask", "age_s": 149, "accept": True}, {"type": "hold", "cls": "member", "age_s": 604800, "accept": True},
    {"type": "hold", "cls": "sign", "accept": False, "note": "class not allowed for type"},
    {"type": "sign", "cls": "sign", "age_s": -31, "accept": False, "note": "dated 31 s ahead"}]

print(json.dumps(out, indent=1, ensure_ascii=False))
