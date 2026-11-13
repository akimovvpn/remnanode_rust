#!/usr/bin/env python3
"""Fetch the pinned official Linux Mihomo client for interoperability tests."""
import argparse
import gzip
import hashlib
from pathlib import Path
import platform
import tempfile
import urllib.request


RELEASE = 'v1.19.34'
SHA256 = {
    'amd64': '223fab877e5795ce780ba39902e5f0b1113c1256ae244a7160f1165e017e9ccc',
    'arm64': 'daaf78a6240a282cdfd75bcbf98fe321f6bd52765cc29e79f344191198f0b50f',
}


def verified_binary(archive, digest):
    if hashlib.sha256(archive).hexdigest() != digest:
        raise ValueError('Mihomo SHA256 verification failed')
    return gzip.decompress(archive)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(platform.machine())
    if platform.system() != 'Linux' or arch is None:
        raise SystemExit('Mihomo interoperability download requires Linux amd64/arm64')
    url = f'https://github.com/MetaCubeX/mihomo/releases/download/{RELEASE}/mihomo-linux-{arch}-{RELEASE}.gz'
    with urllib.request.urlopen(url, timeout=60) as response:
        binary = verified_binary(response.read(), SHA256[arch])
    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='download-', dir=args.output) as temporary:
        target = Path(temporary) / 'mihomo'
        target.write_bytes(binary)
        target.chmod(0o755)
        target.replace(args.output / 'mihomo')
    print(f'Verified Mihomo {RELEASE}: {args.output / "mihomo"}')


if __name__ == '__main__':
    main()
