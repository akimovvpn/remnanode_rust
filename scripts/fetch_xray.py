#!/usr/bin/env python3
"""Download the Xray version pinned in Dockerfile and verify its release digest."""
import argparse
from pathlib import Path
import platform
import re
import tempfile
import urllib.request
import zipfile


def version(dockerfile):
    values = re.findall(r'^ARG XRAY_VERSION=(\S+)\s*$', dockerfile, re.M)
    if len(values) != 1 or not re.fullmatch(r'v\d+\.\d+\.\d+', values[0]):
        raise ValueError('Dockerfile must pin exactly one valid XRAY_VERSION')
    return values[0]


def main():
    from verify_xray import verify
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dockerfile', type=Path, default=Path('Dockerfile'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    release = version(args.dockerfile.read_text())
    system = {'Linux':'linux', 'Darwin':'macos'}.get(platform.system())
    arch = {'x86_64':'64', 'aarch64':'arm64-v8a', 'arm64':'arm64-v8a'}.get(platform.machine())
    if system is None or arch is None:
        raise SystemExit('Only Linux/macOS amd64/arm64 smoke downloads are supported')
    archive = f'Xray-{system}-{arch}.zip'
    base = f'https://github.com/XTLS/Xray-core/releases/download/{release}'
    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='download-', dir=args.output) as temporary:
        stage = Path(temporary)
        for name in (archive, archive + '.dgst'):
            with urllib.request.urlopen(base + '/' + name, timeout=60) as response:
                (stage / name).write_bytes(response.read())
        verify(stage / archive, stage / (archive + '.dgst'))
        with zipfile.ZipFile(stage / archive) as package:
            for name in ('xray', 'geoip.dat', 'geosite.dat'):
                target = stage / name
                target.write_bytes(package.read(name))
                target.chmod(0o755 if name == 'xray' else 0o644)
                target.replace(args.output / name)
    print(f'Verified {release}: {args.output / "xray"}')


if __name__ == '__main__':
    main()
