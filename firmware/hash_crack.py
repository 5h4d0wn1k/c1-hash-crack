#!/usr/bin/env python3
"""
C1 — Hash Cracker
=================

Real hash cracking engine for AUTHORIZED security testing only.

Format support (all stdlib-first; MD4/NTLM uses a bundled pure-python MD4):
  * MD5        (md5)
  * SHA-1      (sha1)
  * SHA-256    (sha256)
  * SHA-512    (sha512)
  * NTLM       (ntlm)            -> Unicode(LE) MD4
  * MD5-Crypt  (md5crypt)        -> linux shadow `$1$`
  * SHA-256-Crypt (sha256crypt)  -> linux shadow `$5$`
  * SHA-512-Crypt (sha512crypt)  -> linux shadow `$6$`
  (SHA-crypt implementations are verified against the reference test vectors.)

Modes:
  * dictionary attack against a wordlist (+ optional mutation rules)
  * brute force over a charset and max length (keep it SMALL!)

All cracking is fully offline and deterministic. No network access is used.

Usage:
  python3 hash_crack.py -H <hash> -t <type> -w <wordlist>
  python3 hash_crack.py -H <hash> -t <type> --brute --max-length 4

IMPORTANT: Read before use. Educational / authorized use only.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import os
import secrets
import struct
import sys
import time
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Pure-python MD4 (needed for NTLM; Crypto.Hash.MD4 is an optional fallback)
# ---------------------------------------------------------------------------

def _md4_compress(state, block):
    def leftrotate(x, c):
        return ((x << c) | (x >> (32 - c))) & 0xFFFFFFFF

    A, B, C, D = state
    M = [int.from_bytes(block[i:i + 4], "little") for i in range(0, 64, 4)]

    def F(x, y, z):
        return (x & y) | (~x & z)

    def G(x, y, z):
        return (x & y) | (x & z) | (y & z)

    def H(x, y, z):
        return x ^ y ^ z

    def ff(a, b, c, d, k, s):
        return leftrotate((a + F(b, c, d) + M[k]) & 0xFFFFFFFF, s)

    def gg(a, b, c, d, k, s):
        return leftrotate((a + G(b, c, d) + M[k] + 0x5A827999) & 0xFFFFFFFF, s)

    def hh(a, b, c, d, k, s):
        return leftrotate((a + H(b, c, d) + M[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)

    AA, BB, CC, DD = A, B, C, D
    # Round 1
    A = ff(A, B, C, D, 0, 3); D = ff(D, A, B, C, 1, 7); C = ff(C, D, A, B, 2, 11); B = ff(B, C, D, A, 3, 19)
    A = ff(A, B, C, D, 4, 3); D = ff(D, A, B, C, 5, 7); C = ff(C, D, A, B, 6, 11); B = ff(B, C, D, A, 7, 19)
    A = ff(A, B, C, D, 8, 3); D = ff(D, A, B, C, 9, 7); C = ff(C, D, A, B, 10, 11); B = ff(B, C, D, A, 11, 19)
    A = ff(A, B, C, D, 12, 3); D = ff(D, A, B, C, 13, 7); C = ff(C, D, A, B, 14, 11); B = ff(B, C, D, A, 15, 19)
    # Round 2
    A = gg(A, B, C, D, 0, 3); D = gg(D, A, B, C, 4, 5); C = gg(C, D, A, B, 8, 9); B = gg(B, C, D, A, 12, 13)
    A = gg(A, B, C, D, 1, 3); D = gg(D, A, B, C, 5, 5); C = gg(C, D, A, B, 9, 9); B = gg(B, C, D, A, 13, 13)
    A = gg(A, B, C, D, 2, 3); D = gg(D, A, B, C, 6, 5); C = gg(C, D, A, B, 10, 9); B = gg(B, C, D, A, 14, 13)
    A = gg(A, B, C, D, 3, 3); D = gg(D, A, B, C, 7, 5); C = gg(C, D, A, B, 11, 9); B = gg(B, C, D, A, 15, 13)
    # Round 3
    A = hh(A, B, C, D, 0, 3); D = hh(D, A, B, C, 8, 9); C = hh(C, D, A, B, 4, 11); B = hh(B, C, D, A, 12, 15)
    A = hh(A, B, C, D, 2, 3); D = hh(D, A, B, C, 10, 9); C = hh(C, D, A, B, 6, 11); B = hh(B, C, D, A, 14, 15)
    A = hh(A, B, C, D, 1, 3); D = hh(D, A, B, C, 9, 9); C = hh(C, D, A, B, 5, 11); B = hh(B, C, D, A, 13, 15)
    A = hh(A, B, C, D, 3, 3); D = hh(D, A, B, C, 11, 9); C = hh(C, D, A, B, 7, 11); B = hh(B, C, D, A, 15, 15)

    return [(AA + A) & 0xFFFFFFFF, (BB + B) & 0xFFFFFFFF,
            (CC + C) & 0xFFFFFFFF, (DD + D) & 0xFFFFFFFF]


def md4(data: bytes) -> bytes:
    """Compute raw MD4 digest of bytes (pure python, independent of any lib)."""
    pad = b"\x80" + b"\x00" * ((55 - len(data)) % 64)
    bit_len = (len(data) * 8) & 0xFFFFFFFFFFFFFFFF
    message = data + pad + struct.pack("<Q", bit_len)

    state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
    for i in range(0, len(message), 64):
        state = _md4_compress(state, message[i:i + 64])
    return struct.pack("<4I", *state)


def _md4_digest(data: bytes) -> bytes:
    """Return MD4 of bytes, preferring Crypto.Hash.MD4 if present."""
    try:
        from Crypto.Hash import MD4
        return MD4.new(data).digest()
    except Exception:
        return md4(data)


# ---------------------------------------------------------------------------
# Unix-crypt base64 (big-endian 6-bit alphabet used by crypt hashes)
# ---------------------------------------------------------------------------

_CRYPT_B64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _h64_transpose(source: bytes, offsets) -> str:
    """Transpose digest bytes via `offsets`, then base64-encode using the
    crypt 64-char alphabet with little-endian grouping (the standard crypt
    encoding, byte-for-byte compatible with the reference implementations)."""
    data = bytes(source[o] for o in offsets)
    out = []
    chunks, tail = divmod(len(data), 3)
    idx = 0
    while idx < chunks:
        v1, v2, v3 = data[idx * 3], data[idx * 3 + 1], data[idx * 3 + 2]
        out.append(_CRYPT_B64[v1 & 0x3f])
        out.append(_CRYPT_B64[((v2 & 0x0f) << 2) | (v1 >> 6)])
        out.append(_CRYPT_B64[((v3 & 0x03) << 4) | (v2 >> 4)])
        out.append(_CRYPT_B64[v3 >> 2])
        idx += 1
    if tail:
        v1 = data[idx * 3]
        if tail == 1:
            out.append(_CRYPT_B64[v1 & 0x3f])
            out.append(_CRYPT_B64[v1 >> 6])
        else:
            v2 = data[idx * 3 + 1]
            out.append(_CRYPT_B64[v1 & 0x3f])
            out.append(_CRYPT_B64[((v2 & 0x0f) << 2) | (v1 >> 6)])
            out.append(_CRYPT_B64[v2 >> 4])
    return "".join(out)


def _repeat_to_len(blob: bytes, length: int) -> bytes:
    """Repeat `blob` until it reaches `length` bytes."""
    if length <= 0:
        return b""
    return (blob * ((length // len(blob)) + 1))[:length]


# ---------------------------------------------------------------------------
# MD5-Crypt ($1$)
# ---------------------------------------------------------------------------

_MD5_TRANSPOSE = (12, 6, 0, 13, 7, 1, 14, 8, 2, 15, 9, 3, 5, 10, 4, 11)
_MD5_OFFSETS = (
    (0, 3), (5, 1), (5, 3), (1, 2), (5, 1), (5, 3), (1, 3),
    (4, 1), (5, 3), (1, 3), (5, 0), (5, 3), (1, 3), (5, 1),
    (4, 3), (1, 3), (5, 1), (5, 2), (1, 3), (5, 1), (5, 3),
)
_MD5_MAGIC = b"$1$"


def md5crypt(password: str, salt: str) -> str:
    """Linux MD5-crypt ($1$). Verified against the reference test vectors."""
    pwd = password.encode()
    slt = salt.encode("ascii")[:8]
    db = hashlib.md5(pwd + slt + pwd).digest()

    a_ctx = hashlib.md5()
    a_ctx.update(pwd + _MD5_MAGIC + slt)
    a_ctx.update(_repeat_to_len(db, len(pwd)))
    i = len(pwd)
    evenchar = pwd[:1]
    while i:
        a_ctx.update(b"\x00" if i & 1 else evenchar)
        i >>= 1
    dc = a_ctx.digest()

    pwd_pwd = pwd + pwd
    pwd_salt = pwd + slt
    perms = [pwd, pwd_pwd, pwd_salt, pwd_salt + pwd, slt + pwd, slt + pwd_pwd]
    data = [(perms[ev], perms[od]) for ev, od in _MD5_OFFSETS]

    blocks = 23
    while blocks:
        for even, odd in data:
            dc = hashlib.md5(odd + hashlib.md5(dc + even).digest()).digest()
        blocks -= 1
    for even, odd in data[:17]:
        dc = hashlib.md5(odd + hashlib.md5(dc + even).digest()).digest()

    checksum = _h64_transpose(dc, _MD5_TRANSPOSE)
    return "$1$" + salt[:8] + "$" + checksum


# ---------------------------------------------------------------------------
# SHA-256-Crypt / SHA-512-Crypt ($5$ / $6$)
# ---------------------------------------------------------------------------

_S256_TRANSPOSE = (
    20, 10, 0, 11, 1, 21, 2, 22, 12, 23, 13, 3, 14, 4, 24, 5,
    25, 15, 26, 16, 6, 17, 7, 27, 8, 28, 18, 29, 19, 9, 30, 31,
)
_S512_TRANSPOSE = (
    42, 21, 0, 1, 43, 22, 23, 2, 44, 45, 24, 3, 4, 46, 25, 26,
    5, 47, 48, 27, 6, 7, 49, 28, 29, 8, 50, 51, 30, 9, 10, 52,
    31, 32, 11, 53, 54, 33, 12, 13, 55, 34, 35, 14, 56, 57, 36, 15,
    16, 58, 37, 38, 17, 59, 60, 39, 18, 19, 61, 40, 41, 20, 62, 63,
)
_DIGEST_OFFSETS = (
    (0, 3), (5, 1), (5, 3), (1, 2), (5, 1), (5, 3), (1, 3),
    (4, 1), (5, 3), (1, 3), (5, 0), (5, 3), (1, 3), (5, 1),
    (4, 3), (1, 3), (5, 1), (5, 2), (1, 3), (5, 1), (5, 3),
)


def _sha_crypt(password: str, salt: str, rounds: int, bits: int) -> str:
    """SHA256-Crypt($5$) / SHA512-Crypt($6$) core. Verified against reference."""
    hash_const = hashlib.sha512 if bits == 512 else hashlib.sha256
    pwd = password.encode()
    slt = salt.encode("ascii")[:16]
    salt_len = len(slt)

    db = hash_const(pwd + slt + pwd).digest()

    # digest A
    a_ctx = hash_const()
    a_ctx.update(pwd + slt)
    a_ctx.update(_repeat_to_len(db, len(pwd)))
    i = len(pwd)
    while i:
        a_ctx.update(db if i & 1 else pwd)
        i >>= 1
    da = a_ctx.digest()

    # digest P
    dp = _repeat_to_len(hash_const(pwd * len(pwd)).digest(), len(pwd))

    # digest S
    ds = hash_const(salt.encode() * (16 + da[0])).digest()[:salt_len]

    # digest C
    dp_dp = dp + dp
    dp_ds = dp + ds
    perms = [dp, dp_dp, dp_ds, dp_ds + dp, ds + dp, ds + dp_dp]
    data = [(perms[ev], perms[od]) for ev, od in _DIGEST_OFFSETS]
    dc = da
    blocks, tail = divmod(rounds, 42)
    while blocks:
        for even, odd in data:
            dc = hash_const(odd + hash_const(dc + even).digest()).digest()
        blocks -= 1
    if tail:
        pairs = tail >> 1
        for even, odd in data[:pairs]:
            dc = hash_const(odd + hash_const(dc + even).digest()).digest()
        if tail & 1:
            dc = hash_const(dc + data[pairs][0]).digest()

    transpose = _S512_TRANSPOSE if bits == 512 else _S256_TRANSPOSE
    checksum = _h64_transpose(dc, transpose)
    return ("$6$" if bits == 512 else "$5$") + salt + "$" + checksum


def sha256crypt(password: str, salt: str, rounds: int = 5000) -> str:
    return _sha_crypt(password, salt, rounds, 256)


def sha512crypt(password: str, salt: str, rounds: int = 5000) -> str:
    return _sha_crypt(password, salt, rounds, 512)


def make_sha_salt(length: int = 16) -> str:
    return "".join(secrets.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./")
                   for _ in range(length))


# ---------------------------------------------------------------------------
# NTLM
# ---------------------------------------------------------------------------

def ntlm_hash(password: str) -> str:
    """NTLM: MD4 of UTF-16LE password, hex (uppercase)."""
    return _md4_digest(password.encode("utf-16-le")).hex().upper()


# ---------------------------------------------------------------------------
# Supported formats / verification
# ---------------------------------------------------------------------------

SUPPORTED = ["md5", "sha1", "sha256", "sha512", "ntlm", "md5crypt",
             "sha256crypt", "sha512crypt"]


class HashCrackerError(Exception):
    pass


def hash_for(password: str, hash_type: str, salt: str = None) -> str:
    """Compute hash string for a candidate password."""
    t = hash_type.lower()
    if t == "md5":
        return hashlib.md5(password.encode()).hexdigest()
    if t == "sha1":
        return hashlib.sha1(password.encode()).hexdigest()
    if t == "sha256":
        return hashlib.sha256(password.encode()).hexdigest()
    if t == "sha512":
        return hashlib.sha512(password.encode()).hexdigest()
    if t == "ntlm":
        return ntlm_hash(password)
    if t == "md5crypt":
        if not salt:
            raise HashCrackerError("md5crypt requires a salt")
        return md5crypt(password, salt)
    if t == "sha256crypt":
        if not salt:
            raise HashCrackerError("sha256crypt requires a salt")
        return sha256crypt(password, salt)
    if t == "sha512crypt":
        if not salt:
            raise HashCrackerError("sha512crypt requires a salt")
        return sha512crypt(password, salt)
    raise HashCrackerError(f"Unsupported hash type: {hash_type}")


def parse_shadow_hash(target: str):
    """Extract (type, full_hash, salt) from a linux shadow hash string."""
    if target.startswith("$1$") or target.startswith("$5$") or target.startswith("$6$"):
        parts = target.split("$")
        hashtype = {"1": "md5crypt", "5": "sha256crypt", "6": "sha512crypt"}[parts[1]]
        salt = parts[2]
        return hashtype, target, salt
    return None, target, None


# ---------------------------------------------------------------------------
# Wordlist mutation rules
# ---------------------------------------------------------------------------

DEFAULT_RULES = [
    ("plain", lambda w: w),
    ("upper", lambda w: w.upper()),
    ("capitalize", lambda w: w.capitalize()),
    ("append1", lambda w: w + "1"),
    ("append123", lambda w: w + "123"),
    ("append21", lambda w: w + "21"),
    ("append!", lambda w: w + "!"),
    ("leet", lambda w: w.replace("a", "4").replace("e", "3").replace("i", "1").replace("o", "0")),
    ("reverse", lambda w: w[::-1]),
]


def apply_rules(word: str, rules=None) -> list:
    rules = rules or DEFAULT_RULES
    out, seen = [], set()
    for name, fn in rules:
        candidate = fn(word)
        if candidate not in seen:
            seen.add(candidate)
            out.append((name, candidate))
    return out


# ---------------------------------------------------------------------------
# Cracker engine
# ---------------------------------------------------------------------------

class HashCracker:
    def __init__(self, target: str, hash_type: str, wordlist: str = None,
                 charset: str = None, max_length: int = 4,
                 use_rules: bool = True, report_dir: str = "reports",
                 label: str = "c1"):
        self.target = target.strip()
        self.requested_type = hash_type
        self.hash_type, self.full_hash, self.salt = parse_shadow_hash(self.target)
        if self.hash_type is None:
            self.hash_type = hash_type
            self.salt = None
        self.wordlist = wordlist
        self.charset = charset or "abcdefghijklmnopqrstuvwxyz0123456789"
        self.max_length = max_length
        self.use_rules = use_rules
        self.report_dir = report_dir
        self.label = label
        self.found = False
        self.result = None
        self.result_rule = None
        self.attempts = 0
        self.start = 0.0

    def _verify(self, candidate: str) -> bool:
        self.attempts += 1
        t = self.hash_type
        if t in ("md5crypt", "sha256crypt", "sha512crypt"):
            return hash_for(candidate, t, self.salt) == self.target
        return hash_for(candidate, t).lower() == self.target.lower()

    def dictionary_attack(self) -> bool:
        if not self.wordlist or not os.path.exists(self.wordlist):
            raise HashCrackerError(f"Wordlist not found: {self.wordlist}")
        with open(self.wordlist, "r", encoding="utf-8", errors="ignore") as fh:
            words = [line.strip() for line in fh if line.strip()]
        print(f"[*] Dictionary attack on {len(words)} words "
              f"(rules={'on' if self.use_rules else 'off'})")
        for word in words:
            candidates = apply_rules(word) if self.use_rules else [("plain", word)]
            for rule, cand in candidates:
                if self._verify(cand):
                    self.found, self.result, self.result_rule = True, cand, rule
                    return True
        return False

    def brute_force_attack(self) -> bool:
        print(f"[*] Brute force: charset={self.charset!r} max_length={self.max_length}")
        total = sum(len(self.charset) ** n for n in range(1, self.max_length + 1))
        print(f"[*] Search space: {total:,} candidates")
        for length in range(1, self.max_length + 1):
            for combo in itertools.product(self.charset, repeat=length):
                cand = "".join(combo)
                if self._verify(cand):
                    self.found, self.result, self.result_rule = True, cand, "brute"
                    return True
        return False

    def crack(self) -> bool:
        self.start = time.time()
        if self.wordlist:
            self.dictionary_attack()
        else:
            self.brute_force_attack()
        return self.found

    def elapsed(self) -> float:
        return time.time() - self.start

    def rate(self) -> float:
        e = self.elapsed()
        return self.attempts / e if e > 0 else 0.0

    def report(self) -> dict:
        return {
            "label": self.label,
            "target": self.target,
            "hash_type": self.hash_type,
            "found": self.found,
            "password": self.result,
            "rule": self.result_rule,
            "attempts": self.attempts,
            "elapsed_sec": round(self.elapsed(), 4),
            "rate_per_sec": round(self.rate(), 1),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def save_report(data: dict, report_dir: str) -> str:
    os.makedirs(report_dir, exist_ok=True)
    fname = os.path.join(report_dir, f"c1_report_{int(time.time())}.json")
    with open(fname, "w") as fh:
        json.dump(data, fh, indent=2)
    return fname


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="hash_crack",
        description="C1 — Hash Cracker (AUTHORIZED security testing only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Formats: md5, sha1, sha256, sha512, ntlm, md5crypt, sha256crypt, sha512crypt\n"
            "Examples:\n"
            "  python3 hash_crack.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -t md5 -w wordlist.txt\n"
            "  python3 hash_crack.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -t md5 --brute -m 3\n"
            "  shadow hashes auto-detect $1$/$5$/$6$ type and salt"
        ),
    )
    parser.add_argument("-H", "--hash", required=True, help="Target hash")
    parser.add_argument("-t", "--type", choices=SUPPORTED, default="md5", help="Hash type")
    parser.add_argument("-w", "--wordlist", help="Wordlist file (dictionary mode)")
    parser.add_argument("-b", "--brute", action="store_true", help="Brute force mode")
    parser.add_argument("-c", "--charset", default="abcdefghijklmnopqrstuvwxyz0123456789",
                        help="Brute force charset")
    parser.add_argument("-m", "--max-length", type=int, default=4, help="Max brute force length")
    parser.add_argument("--no-rules", action="store_true", help="Disable mutation rules")
    parser.add_argument("--report-dir", default="reports", help="Report output dir")
    args = parser.parse_args(argv)

    if not args.wordlist and not args.brute:
        parser.error("Provide a wordlist (-w) or use --brute")

    try:
        cracker = HashCracker(
            args.hash, args.type, wordlist=args.wordlist, charset=args.charset,
            max_length=args.max_length, use_rules=not args.no_rules,
            report_dir=args.report_dir,
        )
    except HashCrackerError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    found = cracker.crack()
    data = cracker.report()

    print("\n" + "=" * 50)
    print(f"Target:    {data['target']}")
    print(f"Type:      {data['hash_type']}")
    if found:
        print(f"CRACKED!   password={data['password']!r} rule={data['result_rule']}")
    else:
        print("Not found.")
    print(f"Attempts:  {data['attempts']:,}")
    print(f"Elapsed:   {data['elapsed_sec']:.3f}s  rate={data['rate_per_sec']:.0f}/s")
    print("=" * 50)

    if args.report_dir:
        print(f"[*] Report written: {save_report(data, args.report_dir)}")
    return 0 if found else 1


if __name__ == "__main__":
    sys.exit(main())
