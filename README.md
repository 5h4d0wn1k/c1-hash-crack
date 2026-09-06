# C1 — Hash Cracker

A real, offline, deterministic hash cracking engine for **authorized security
testing only**. Supports multiple hash formats, dictionary attacks with
mutation rules, and small brute-force searches, all with no network access.

## IMPORTANT: Read before use.

**This tool is for educational and authorized security testing purposes only.**

- You MUST have explicit written authorization before attempting to crack any
  hash that you do not own.
- Cracking passwords without authorization may violate the **Computer Fraud and
  Abuse Act (CFAA)**, state computer-crime statutes, and privacy regulations
  (GDPR/CCPA). You are solely responsible for lawful use.
- Use only on your own systems or within a defined lab/scope (e.g. lab-* hosts,
  192.0.2.x ranges, example.com).
- This software is provided "AS IS" with no warranty; the author is not liable
  for misuse or damage.

## What genuinely works (real mechanics)

- **SHA/MD5 single hashes**: MD5, SHA-1, SHA-256, SHA-512 via `hashlib`.
- **NTLM**: MD4 of UTF-16LE password (pure-python MD4 bundled; falls back to
  `Crypto.Hash.MD4` if pycryptodome is present).
- **Linux shadow formats** (implemented and verified against reference vectors):
  - `$1$` MD5-Crypt
  - `$5$` SHA-256-Crypt
  - `$6$` SHA-512-Crypt
  (Type and salt are auto-detected when a `$1$/$5$/$6$` hash is supplied.)
- **Wordlist attack** with configurable **mutation rules** (case, appends,
  leetspeak, reverse).
- **Brute force** over a charset and max length (keep it small — it is
  exhaustive).
- **Timing / reporting**: attempts, elapsed seconds, rate, and JSON reports.

All shadow hash implementations are tested against authoritative reference
vectors so the engine is trustworthy for lab verification.

## Requirements

- Python 3.8+ (standard library only for the core engine).
- Optional: `pycryptodome` (used for MD4 if present, otherwise pure-python MD4
  is used).

## Usage

```bash
# List options
python3 firmware/hash_crack.py --help

# Dictionary attack
python3 firmware/hash_crack.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -t md5 -w fixtures/wordlist.txt

# Password present only as a mutation ("orange" -> "orange123")
python3 firmware/hash_crack.py -H <sha256 of orange123> -t sha256 -w fixtures/wordlist.txt

# Small brute force (max length 3)
python3 firmware/hash_crack.py -H <md5> -t md5 --brute -c abc -m 3

# Linux shadow hash (auto-detects type and salt)
python3 firmware/hash_crack.py -H '$6$...' -t sha512crypt -w fixtures/wordlist.txt
```

## Demo (offline, deterministic)

```bash
python3 demo.py
```

Cracks a known plaintext for each supported format and prints timing. Exits 0
on success.

## Tests

```bash
python3 -m unittest discover -s tests
```

Validates hash implementations against reference vectors plus end-to-end
cracking.

## Live Lab Test Plan

Intended to run against an authorized lab environment only:

1. **Unit/hash verification (offline)**: `python3 -m unittest discover -s tests`
   — confirms MD5/SHA/NTLM and all shadow formats reproduce known values.
2. **Offline demo**: `python3 demo.py` — confirms each format cracks a known
   plaintext deterministically.
3. **Lab dictionary run**: deploy `fixtures/wordlist.txt` (or an authorized
   wordlist) on a lab-* host and crack self-generated hashes.
4. **Shadow-crypt cross-check**: generate a `$6$` shadow line on a lab host
   with `mkpasswd -m sha-512` and compare — the engine must reproduce it.
5. **Rate/timing measurement**: run the CLI against a large authorized wordlist
   and record `attempts`, `elapsed_sec`, `rate_per_sec`.
6. **Negative control**: verify an uncrackable hash returns exit code 1.

Run everything on lab infrastructure; never on production or third-party
targets without written scope.

## Metrics

- Formats supported: **8** (md5, sha1, sha256, sha512, ntlm,
  md5crypt, sha256crypt, sha512crypt).
- Cracking modes: dictionary (+rules), brute force.
- Reference-vector tests: Linux shadow hashes verified byte-for-byte;
  NTLM verified against the canonical `8846F7EAEE8FB117AD06BDD830B7586C`.
- SHA-512-Crypt round count: 5000 (standard default) per hash; verify reduces
  only when the target is found.
- Deterministic: fixed salts/wordlists produce identical results run to run.
- Output: JSON reports under `reports/`, human-readable timing to stdout.

## License

MIT
