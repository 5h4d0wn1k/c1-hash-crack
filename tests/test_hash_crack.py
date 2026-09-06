#!/usr/bin/env python3
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from firmware import hash_crack as hc


class TestShadows(unittest.TestCase):
    """Hash implementations must match authoritative reference vectors."""

    def test_md5crypt_reference(self):
        self.assertEqual(hc.md5crypt("password", "12345678"),
                         "$1$12345678$o2n/JiO/h5VviOInWJ4OQ/")
        self.assertEqual(hc.md5crypt("abc", "xyz"),
                         "$1$xyz$rzmaHv.aP/Z0w4eY/XX2u1")

    def test_sha256crypt_reference(self):
        self.assertEqual(hc.sha256crypt("password", "12345678"),
                         "$5$12345678$HxSvzMyVSg03Aq96z9E/GySiT7BkyOSTDjfKSua5oY2")
        self.assertEqual(hc.sha256crypt("abc", "xyz"),
                         "$5$xyz$sHgIl3fGpAkUQkiCZJd2eoLwmevLjCIH29vySCugJh1")

    def test_sha512crypt_reference(self):
        self.assertEqual(hc.sha512crypt("password", "12345678"),
                         "$6$12345678$I8tr4xFAC6/TtjYWdp0LWEjQre2LcYm2jdSMNLQDIyqRv.cKo7KMD5/HpzVVFKpUQlIekr/Vw.OdImtRM85fg/")
        self.assertEqual(hc.sha512crypt("abc", "xyz"),
                         "$6$xyz$PAKvmleneF76dJMCB7ba8K2HKOKSvc4SaCsFDIbfDYCnv235b1miMic/DW32Fag7jQfkhMyoBttnxSERDybni.")

    def test_sha512crypt_empty(self):
        self.assertEqual(hc.sha512crypt("", ""),
                         "$6$$/chiBau24cE26QQVW3IfIe68Xu5.JQ4E8Ie7lcRLwqxO5cxGuBhqF2HmTL.zWJ9zjChg3yJYFXeGBQ2y3Ba1d1")


class TestNTLM(unittest.TestCase):
    def test_ntlm_reference(self):
        self.assertEqual(hc.ntlm_hash("password").upper(), "8846F7EAEE8FB117AD06BDD830B7586C")

    def test_ntlm_roundtrip(self):
        self.assertEqual(hc.ntlm_hash("labdemo").upper(), hc.hash_for("labdemo", "ntlm").upper())


class TestSimpleHashes(unittest.TestCase):
    def test_md5(self):
        self.assertEqual(hc.hash_for("labdemo", "md5"),
                         hc.hashlib.md5(b"labdemo").hexdigest())

    def test_sha1_sha256_sha512(self):
        self.assertEqual(hc.hash_for("labdemo", "sha1"), hc.hashlib.sha1(b"labdemo").hexdigest())
        self.assertEqual(hc.hash_for("labdemo", "sha256"), hc.hashlib.sha256(b"labdemo").hexdigest())
        self.assertEqual(hc.hash_for("labdemo", "sha512"), hc.hashlib.sha512(b"labdemo").hexdigest())


class TestMD4(unittest.TestCase):
    def test_md4_vector(self):
        # RFC 1320 test vector for "abc"
        result = hc.md4(b"\x61\x62\x63")  # "abc"
        expected = bytes.fromhex("a448017aaf21d8525fc10ae87aa6729d")
        self.assertEqual(result, expected)

    def test_md4_matches_crypto_if_available(self):
        try:
            from Crypto.Hash import MD4
        except Exception:
            self.skipTest("pycryptodome not available")
        for p in ("password", "labdemo", "hello"):
            self.assertEqual(hc.md4(p.encode("utf-16-le")),
                             MD4.new(p.encode("utf-16-le")).digest())


class TestRules(unittest.TestCase):
    def test_rules_dedup(self):
        cands = hc.apply_rules("Orange")
        names = [n for n, c in cands]
        self.assertEqual(len(cands), len(set(names)))

    def test_rules_produce_mutations(self):
        cands = hc.apply_rules("orange")
        strings = [c for _, c in cands]
        self.assertIn("orange123", strings)
        self.assertIn("ORANGE", strings)
        self.assertIn("0r4ng3", strings)


class TestCracking(unittest.TestCase):
    def _crack(self, target, hashtype, wordlist):
        c = hc.HashCracker(target, hashtype, wordlist=wordlist)
        self.assertTrue(c.crack(), f"failed to crack {hashtype}")
        return c

    def test_md5_crack(self):
        wordlist = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "fixtures", "wordlist.txt")
        c = self._crack(hc.hash_for("labdemo", "md5"), "md5", wordlist)
        self.assertEqual(c.result, "labdemo")

    def test_ntlm_crack(self):
        wordlist = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "fixtures", "wordlist.txt")
        c = self._crack(hc.hash_for("trustno1", "ntlm"), "ntlm", wordlist)
        self.assertEqual(c.result, "trustno1")

    def test_shadow_crack_autodetect(self):
        wordlist = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "fixtures", "wordlist.txt")
        target = hc.sha512crypt("iloveyou", "lababcdef")
        c = self._crack(target, "sha512crypt", wordlist)
        self.assertEqual(c.result, "iloveyou")
        self.assertEqual(c.hash_type, "sha512crypt")

    def test_brute_force(self):
        c = hc.HashCracker(hc.hash_for("cab", "md5"), "md5",
                           wordlist=None, charset="abc", max_length=3, use_rules=False)
        self.assertTrue(c.crack())
        self.assertEqual(c.result, "cab")

    def test_negative_brute(self):
        c = hc.HashCracker(hc.hash_for("zzzz", "md5"), "md5",
                           wordlist=None, charset="a", max_length=3, use_rules=False)
        self.assertFalse(c.crack())


class TestCLI(unittest.TestCase):
    def test_cli_help(self):
        from io import StringIO
        old = sys.argv
        sys.argv = ["hash_crack", "--help"]
        try:
            with self.assertRaises(SystemExit) as ctx:
                hc.main()
            self.assertIn(ctx.exception.code, (0, None))
        finally:
            sys.argv = old

    def test_cli_requires_mode(self):
        old = sys.argv
        sys.argv = ["hash_crack", "-H", "abc"]
        try:
            with self.assertRaises(SystemExit):
                hc.main()
        finally:
            sys.argv = old


if __name__ == "__main__":
    unittest.main()
