#!/usr/bin/env python3
"""Verify an official Xray release archive against its published SHA256 digest."""
import hashlib
from pathlib import Path
import re
import sys


def verify(archive, digest):
    values = re.findall(r'^SHA2-256= ([0-9a-fA-F]{64})\s*$', digest.read_text(), re.M)
    if len(values) != 1 or hashlib.sha256(archive.read_bytes()).hexdigest() != values[0].lower():
        raise ValueError('Xray SHA256 verification failed')


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('Usage: verify_xray.py ARCHIVE DIGEST')
    verify(Path(sys.argv[1]), Path(sys.argv[2]))
