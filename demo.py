#!/usr/bin/env python3
"""
C1 — Hash Cracker: offline demo.

Cracks a known plaintext from each supported format to prove real mechanics.
All offline, all deterministic, exits 0 on success.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from firmware import hash_crack as hc

WORDLIST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "wordlist.txt")


def demo_format(target, hashtype, wordlist=WORDLIST, **kw):
    print(f"\n--- {hashtype} ---")
    cracker = hc.HashCracker(target, hashtype, wordlist=wordlist, **kw)
    found = cracker.crack()
    data = cracker.report()
    assert found, f"{hashtype} crack FAILED"
    print(f"cracked={data['password']!r} rule={data['rule']} "
          f"attempts={data['attempts']} elapsed={data['elapsed_sec']:.3f}s")
    return data


def main():
    print("C1 Hash Cracker — offline demo (authorized lab hashes only)")
    results = []

    # 1. MD5 of 'labdemo' (present in the fixture wordlist)
    results.append(demo_format(hc.hash_for("labdemo", "md5"), "md5"))

    # 2. SHA-256 of 'orange' via a mutation rule (wordlist has 'orange', rule appends '123')
    results.append(demo_format(hc.hash_for("orange123", "sha256"), "sha256"))

    # 3. SHA-512 of 'secret'
    results.append(demo_format(hc.hash_for("secret", "sha512"), "sha512"))

    # 4. NTLM of 'trustno1'
    results.append(demo_format(hc.hash_for("trustno1", "ntlm"), "ntlm"))

    # 5. MD5-Crypt ($1$) of 'qwerty' with a fixed lab salt
    salt1 = "labab"
    results.append(demo_format(hc.md5crypt("qwerty", salt1), "md5crypt"))

    # 6. SHA-256-Crypt ($5$) of 'letmein'
    salt5 = "lababc"
    results.append(demo_format(hc.sha256crypt("letmein", salt5), "sha256crypt"))

    # 7. SHA-512-Crypt ($6$) of 'iloveyou'
    salt6 = "lababcdef"
    results.append(demo_format(hc.sha512crypt("iloveyou", salt6), "sha512crypt"))

    # 8. Brute force md5 of a 3-char password ('cab') over charset abc
    ok = demo_format(hc.hash_for("cab", "md5"), "md5",
                     wordlist=None, charset="abc", max_length=3, use_rules=False)
    results.append(ok)

    print("\nAll offline demos PASSED:", len(results), "formats")
    for r in results:
        hc.save_report(r, os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
