# C1 — Hash Cracker

Multi-algorithm hash cracker for authorized security testing.

## Overview

This project implements a hash cracking tool that:
- Supports MD5, SHA1, SHA256, SHA512, bcrypt, NTLM
- Dictionary attack with wordlists
- Brute force attack with configurable charset
- Multi-threaded cracking for speed
- Rainbow table lookup support

## Features

- **Multiple algorithms**: MD5, SHA1, SHA256, SHA512, bcrypt, NTLM
- **Dictionary attack**: Use wordlists (rockyou.txt, etc.)
- **Brute force**: Try all combinations up to max length
- **Progress tracking**: Real-time progress and rate display
- **Password variations**: Auto-try common modifications

## Installation

```bash
pip install bcrypt
```

## Usage

```bash
# Dictionary attack
python3 hash_crack.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -t md5 -w rockyou.txt

# Brute force (short passwords only!)
python3 hash_crack.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -t md5 -c abc123 -m 4
```

## Example Output

```
=== C1 — Hash Cracker ===
Target: 5f4dcc3b5aa765d61d8327deb882cf99
Type:   md5
Mode:   Dictionary

Starting dictionary attack...
Wordlist: rockyou.txt
Words: 14341564

Cracking...

  Progress: 12.3% | Attempts: 1764012 | Rate: 15234/s

*** HASH CRACKED! ***
Password: password
Attempts: 2345678
Time: 154.23 seconds
Rate: 15207 attempts/sec
```

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**. 

### Authorization Requirements
- You MUST have explicit written permission before cracking passwords
- Unauthorized password cracking is illegal under federal and state laws
- This tool should ONLY be used on hashes you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Identity Theft Laws**: Using cracked passwords for impersonation is illegal
- **State Laws**: Many states have additional computer crime statutes
- **GDPR/CCPA**: Password data may be subject to privacy regulations

### Acceptable Use
- Testing password strength on your own systems
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Cracking passwords without authorization
- Using cracked passwords for unauthorized access
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
