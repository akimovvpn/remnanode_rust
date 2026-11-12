#!/usr/bin/env python3
"""Reject a supported baseline whose bundled engine versions were not ported."""
import json
from pathlib import Path
import re


def check(manifest, dockerfile):
    for artifact, argument in [('xray', 'XRAY_VERSION'), ('geocheck', 'GEOCHECK_VERSION')]:
        expected = manifest['artifacts'][artifact]
        values = re.findall(r'^ARG ' + argument + r'=(\S+)\s*$', dockerfile, re.M)
        if values != [expected]:
            raise ValueError(f'{argument} must match supported upstream {expected}; found {values}')


if __name__ == '__main__':
    root = Path(__file__).resolve().parents[1]
    check(json.loads((root / 'upstream/manifest.json').read_text()), (root / 'Dockerfile').read_text())
    print('Bundled artifact pins match the supported upstream baseline')
