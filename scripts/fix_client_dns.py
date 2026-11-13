#!/usr/bin/env python3
"""Route client DNS requests through its existing Xray split DNS configuration."""
import copy
import argparse
import json
import os
from pathlib import Path
import tempfile


def patch_config(config):
    if not isinstance(config, dict) or not isinstance(config.get('dns'), dict):
        raise ValueError('expected an Xray JSON object with an existing dns object')
    result = copy.deepcopy(config)
    servers = result['dns'].get('servers')
    if not isinstance(servers, list) or not servers:
        raise ValueError('dns.servers must be a nonempty list')
    retained = []
    for server in servers:
        address = server.get('address') if isinstance(server, dict) else server
        if not isinstance(address, str) or not address:
            raise ValueError('each DNS server must have a nonempty address')
        if address != 'localhost':
            retained.append(server)
    if not retained:
        raise ValueError('removing localhost would leave no configured DNS servers')

    tags = []
    for name in ['inbounds', 'outbounds']:
        entries = result.get(name)
        if not isinstance(entries, list) or not entries or not all(isinstance(x, dict) for x in entries):
            raise ValueError(f'{name} must be a nonempty list of objects')
        used = set()
        for entry in entries:
            if not isinstance(entry.get('protocol'), str) or not entry['protocol']:
                raise ValueError(f'{name} entries need a nonempty protocol')
            tag = entry.get('tag', '')
            if not isinstance(tag, str) or (tag and tag in used):
                raise ValueError(f'{name} tags must be strings and unique')
            used.add(tag)
            if name == 'inbounds' and entry.get('protocol') in ('socks', 'http'):
                if not tag:
                    raise ValueError('SOCKS/HTTP inbounds need tags to scope DNS interception')
                tags.append(tag)
    if not tags:
        raise ValueError('no tagged SOCKS/HTTP inbound found')
    routing = result.setdefault('routing', {})
    if not isinstance(routing, dict):
        raise ValueError('routing must be an object')
    rules = routing.setdefault('rules', [])
    if not isinstance(rules, list) or not all(isinstance(x, dict) for x in rules):
        raise ValueError('routing.rules must be a list of objects')

    outbounds = result['outbounds']
    dns_out = next((x for x in outbounds if x.get('tag') and x.get('protocol') == 'dns'
                    and x.get('settings', {}) == {}), None)
    if dns_out is None:
        occupied = {x.get('tag') for x in outbounds}
        tag, suffix = 'dns-out', 0
        while tag in occupied:
            suffix += 1
            tag = f'dns-out-{suffix}'
        dns_out = {'tag': tag, 'protocol': 'dns', 'settings': {}}
        outbounds.append(dns_out)
    rule = {'type': 'field', 'inboundTag': tags, 'network': 'tcp,udp',
            'port': '53', 'outboundTag': dns_out['tag']}
    if rule in rules:
        rules.remove(rule)
    rules.insert(0, rule)
    result['dns']['servers'] = retained
    return result


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON object keys are ambiguous')
        result[key] = value
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path, help='existing client Xray JSON')
    parser.add_argument('output', type=Path, help='new output file; existing files are never replaced')
    args = parser.parse_args()
    temporary = None
    try:
        if args.input.resolve() == args.output.resolve():
            raise ValueError('input and output must be different paths')
        config = json.loads(args.input.read_text(encoding='utf-8'), object_pairs_hook=unique_object)
        fixed = patch_config(config)
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=args.output.parent,
                                         prefix='.client-dns-', delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(fixed, stream, ensure_ascii=False, indent=2, allow_nan=False)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        # Publish atomically without replacing a file created concurrently.
        os.link(temporary, args.output)
    except (OSError, ValueError, TypeError):
        parser.exit(1, 'Cannot patch config: check JSON shape and use a new, writable output path.\n')
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


if __name__ == '__main__':
    main()
