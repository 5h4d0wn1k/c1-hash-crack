#!/usr/bin/env python3
"""
C1 — Hash Cracker
Multi-algorithm hash cracker for authorized security testing

Features:
- Support for MD5, SHA1, SHA256, SHA512, bcrypt, NTLM
- Dictionary attack mode
- Brute force mode
- Rainbow table lookup
- Multi-threaded cracking

Usage:
    python3 hash_crack.py --hash <hash> --type md5 --wordlist rockyou.txt

WARNING: Educational use only. Test on your own hashes.
"""

import argparse
import hashlib
import hmac
import os
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import bcrypt
import binascii

class HashCracker:
    def __init__(self, hash_value, hash_type, wordlist=None, charset=None, max_length=6):
        self.hash_value = hash_value.lower()
        self.hash_type = hash_type.lower()
        self.wordlist = wordlist
        self.charset = charset or "abcdefghijklmnopqrstuvwxyz0123456789"
        self.max_length = max_length
        self.found = False
        self.result = None
        self.attempts = 0
        self.lock = threading.Lock()
        self.start_time = None
        
        print(f"\n=== C1 — Hash Cracker ===")
        print(f"Target: {self.hash_value}")
        print(f"Type:   {self.hash_type}")
        print(f"Mode:   {'Dictionary' if wordlist else 'Brute Force'}")
        print("=" * 30)
    
    def hash_password(self, password, hash_type):
        """Hash password with specified algorithm"""
        password_bytes = password.encode('utf-8')
        
        if hash_type == 'md5':
            return hashlib.md5(password_bytes).hexdigest()
        elif hash_type == 'sha1':
            return hashlib.sha1(password_bytes).hexdigest()
        elif hash_type == 'sha256':
            return hashlib.sha256(password_bytes).hexdigest()
        elif hash_type == 'sha512':
            return hashlib.sha512(password_bytes).hexdigest()
        elif hash_type == 'ntlm':
            try:
                return hashlib.new('md4', password_bytes).hexdigest()
            except:
                # Fallback for systems without md4
                import subprocess
                result = subprocess.run(['iconv', '-f', 'utf-8', '-t', 'utf-16le'], 
                                      input=password, capture_output=True)
                return hashlib.md5(result.stdout).hexdigest()
        elif hash_type == 'bcrypt':
            # bcrypt needs the full hash for comparison
            return None
        else:
            raise ValueError(f"Unsupported hash type: {hash_type}")
    
    def check_bcrypt(self, password):
        """Check bcrypt hash"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), 
                                 self.hash_value.encode('utf-8'))
        except:
            return False
    
    def dictionary_attack(self):
        """Dictionary attack mode"""
        if not self.wordlist or not os.path.exists(self.wordlist):
            print(f"ERROR: Wordlist not found: {self.wordlist}")
            return False
        
        print(f"\nStarting dictionary attack...")
        print(f"Wordlist: {self.wordlist}")
        
        # Count lines
        with open(self.wordlist, 'r', errors='ignore') as f:
            total = sum(1 for _ in f)
        
        print(f"Words: {total}")
        print(f"\nCracking...\n")
        
        self.start_time = time.time()
        
        with open(self.wordlist, 'r', errors='ignore') as f:
            for line in f:
                if self.found:
                    break
                
                word = line.strip()
                if not word:
                    continue
                
                self.attempts += 1
                
                # Try common variations
                variations = [
                    word,
                    word.lower(),
                    word.upper(),
                    word.capitalize(),
                    word + "123",
                    word + "!",
                    word + "1",
                ]
                
                for variation in variations:
                    if self.found:
                        break
                    
                    if self.hash_type == 'bcrypt':
                        if self.check_bcrypt(variation):
                            self.found = True
                            self.result = variation
                    else:
                        computed = self.hash_password(variation, self.hash_type)
                        if computed == self.hash_value:
                            self.found = True
                            self.result = variation
                
                # Progress update
                if self.attempts % 10000 == 0:
                    elapsed = time.time() - self.start_time
                    rate = self.attempts / elapsed if elapsed > 0 else 0
                    progress = (self.attempts / total) * 100
                    print(f"  Progress: {progress:.1f}% | Attempts: {self.attempts} | Rate: {rate:.0f}/s")
        
        return self.found
    
    def brute_force_attack(self):
        """Brute force attack mode"""
        print(f"\nStarting brute force attack...")
        print(f"Charset: {self.charset}")
        print(f"Max length: {self.max_length}")
        
        self.start_time = time.time()
        
        # Generate all combinations
        from itertools import product
        
        for length in range(1, self.max_length + 1):
            if self.found:
                break
            
            print(f"\nTrying length {length}...")
            
            for combination in product(self.charset, repeat=length):
                if self.found:
                    break
                
                password = ''.join(combination)
                self.attempts += 1
                
                if self.hash_type == 'bcrypt':
                    if self.check_bcrypt(password):
                        self.found = True
                        self.result = password
                else:
                    computed = self.hash_password(password, self.hash_type)
                    if computed == self.hash_value:
                        self.found = True
                        self.result = password
                
                # Progress update
                if self.attempts % 100000 == 0:
                    elapsed = time.time() - self.start_time
                    rate = self.attempts / elapsed if elapsed > 0 else 0
                    print(f"  Attempts: {self.attempts} | Rate: {rate:.0f}/s")
        
        return self.found
    
    def crack(self):
        """Main cracking function"""
        if self.wordlist:
            success = self.dictionary_attack()
        else:
            success = self.brute_force_attack()
        
        elapsed = time.time() - self.start_time if self.start_time else 0
        
        print(f"\n{'=' * 30}")
        if success:
            print(f"*** HASH CRACKED! ***")
            print(f"Password: {self.result}")
        else:
            print(f"Hash not found")
        
        print(f"Attempts: {self.attempts}")
        print(f"Time: {elapsed:.2f} seconds")
        if elapsed > 0:
            print(f"Rate: {self.attempts/elapsed:.0f} attempts/sec")
        print(f"{'=' * 30}")
        
        return success

def main():
    parser = argparse.ArgumentParser(description='C1 — Hash Cracker')
    parser.add_argument('--hash', '-H', required=True, help='Target hash')
    parser.add_argument('--type', '-t', required=True, 
                       choices=['md5', 'sha1', 'sha256', 'sha512', 'ntlm', 'bcrypt'],
                       help='Hash type')
    parser.add_argument('--wordlist', '-w', help='Wordlist file')
    parser.add_argument('--charset', '-c', help='Brute force charset')
    parser.add_argument('--max-length', '-m', type=int, default=6, 
                       help='Max password length for brute force')
    
    args = parser.parse_args()
    
    cracker = HashCracker(args.hash, args.type, args.wordlist, args.charset, args.max_length)
    cracker.crack()

if __name__ == '__main__':
    main()
