#!/usr/bin/env python3
"""Switch an existing node Compose file to the Rust node and Rust core."""
import argparse
import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import tempfile

IMAGE = 'ghcr.io/akimovvpn/remnanode_rust:latest'
CORE = '/usr/local/bin/rcore'
OLD_IMAGES = ('remnawave/node:latest', 'ghcr.io/remnawave/node:latest', IMAGE)


def significant(line):
    return bool(line.strip()) and not line.lstrip().startswith('#')


def indent(line):
    return len(line) - len(line.lstrip(' '))


def rewrite(text):
    lines = text.splitlines(keepends=True)
    newline = '\r\n' if '\r\n' in text else '\n'
    roots = [i for i, line in enumerate(lines)
             if re.fullmatch(r' *services:[ \t]*(?:#.*)?', line.rstrip('\r\n'))]
    if len(roots) != 1:
        raise ValueError('Expected one block-style services section; file unchanged')
    start = roots[0]
    end = next((i for i in range(start + 1, len(lines))
                if significant(lines[i]) and indent(lines[i]) <= indent(lines[start])), len(lines))
    children = [i for i in range(start + 1, end) if significant(lines[i])]
    if not children:
        raise ValueError('No services found; file unchanged')
    service_indent = min(indent(lines[i]) for i in children)
    cuts = [i for i in children if indent(lines[i]) == service_indent] + [end]
    image_pattern = re.compile(r'^( +)image:[ \t]*([\'"]?)(' +
                               '|'.join(re.escape(x) for x in OLD_IMAGES) +
                               r')\2[ \t]*(?:#.*)?$')
    matches = []
    for begin, finish in zip(cuts, cuts[1:]):
        properties = [i for i in range(begin + 1, finish) if significant(lines[i])]
        if not properties:
            continue
        level = min(indent(lines[i]) for i in properties)
        for i in properties:
            match = image_pattern.fullmatch(lines[i].rstrip('\r\n'))
            if match and indent(lines[i]) == level:
                matches.append((i, begin, finish, match))
    if len(matches) != 1:
        raise ValueError('Expected exactly one node with an official latest or Rust image; file unchanged')
    image, begin, finish, match = matches[0]
    spaces = match[1]
    lines[image] = lines[image][:match.start(3)] + IMAGE + lines[image][match.end(3):]
    environments = [i for i in range(begin + 1, finish)
                    if re.match(r'^' + spaces + r'environment:', lines[i])]
    if len(environments) > 1:
        raise ValueError('Duplicate environment sections; file unchanged')
    if not environments:
        if not lines[image].endswith('\n'):
            lines[image] += newline
        lines[image + 1:image + 1] = [spaces + 'environment:' + newline,
                                    spaces + '  - XRAY_BINARY=' + CORE + newline]
        return ''.join(lines)
    env = environments[0]
    value = lines[env].split(':', 1)[1].split('#', 1)[0].strip()
    # shortcut: preserve block YAML text; refuse inline/anchor values rather than reserialize secrets.
    if value not in ('', '{}', '[]', 'null', '~'):
        raise ValueError('Inline or anchored environment is unsupported; file unchanged')
    env_end = next((i for i in range(env + 1, finish)
                    if significant(lines[i]) and indent(lines[i]) <= len(spaces)
                    and not (indent(lines[i]) == len(spaces) and lines[i].lstrip().startswith('-'))), finish)
    items = [line for line in lines[env + 1:env_end] if significant(line)]
    level = min(map(indent, items)) if items else len(spaces) + 2
    sequence = not items or items[0].lstrip().startswith('-')
    if sequence:
        key = re.compile(r'^' + ' ' * level + r'-[ \t]*[\'"]?XRAY_BINARY(?:=|[\'"]?[ \t]*(?:#.*)?$)')
        setting = ' ' * level + '- XRAY_BINARY=' + CORE + newline
    else:
        key = re.compile(r'^' + ' ' * level + r'([\'"]?)XRAY_BINARY\1[ \t]*:')
        setting = ' ' * level + 'XRAY_BINARY: ' + CORE + newline
    body, replaced = [], False
    for line in lines[env + 1:env_end]:
        if key.match(line.rstrip('\r\n')):
            if not replaced:
                body.append(setting)
            replaced = True
        else:
            body.append(line)
    if not replaced:
        if body and not body[-1].endswith('\n'):
            body[-1] += newline
        body.append(setting)
    header = lines[env] if not value else spaces + 'environment:' + newline
    if not header.endswith('\n'):
        header += newline
    lines[env:env_end] = [header] + body
    return ''.join(lines)


def compose_model(path):
    result = subprocess.run(
        ['docker', 'compose', '--project-directory', str(path.parent), '-f', str(path),
         'config', '--format', 'json'], cwd=path.parent, capture_output=True, text=True)
    if result.returncode:
        # Compose diagnostics can contain configuration values; never print them here.
        raise ValueError('Docker Compose validation failed; file unchanged')
    return json.loads(result.stdout)


def migrate(path):
    path = Path(path).resolve(strict=True)
    original = path.read_bytes()
    before = compose_model(path)
    services = [name for name, service in before['services'].items()
                if service.get('image') in OLD_IMAGES]
    if len(services) != 1:
        raise ValueError('Expected exactly one official latest or Rust node service; file unchanged')
    name = services[0]
    if before['services'][name].get('build'):
        raise ValueError('Node has a build setting; remove it before switching images')
    updated = rewrite(original.decode('utf-8')).encode('utf-8')
    if updated == original:
        return None
    expected = copy.deepcopy(before)
    node = expected['services'][name]
    node['image'] = IMAGE
    node['environment'] = {**(node.get('environment') or {}), 'XRAY_BINARY': CORE}
    metadata = path.stat()
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '.rust-', suffix='.yml', dir=path.parent)
    temporary = Path(temporary)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            os.fchmod(output.fileno(), stat.S_IMODE(metadata.st_mode))
            os.fchown(output.fileno(), metadata.st_uid, metadata.st_gid)
            output.write(updated)
            output.flush()
            os.fsync(output.fileno())
        if compose_model(temporary) != expected:
            raise ValueError('Unexpected Compose changes beyond image/XRAY_BINARY; file unchanged')
        if path.read_bytes() != original:
            raise ValueError('Compose file changed during migration; run again')
        backup = path.with_name(path.name + '.bak.' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
        with backup.open('xb') as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(original)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        return backup
    finally:
        temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file', nargs='?', type=Path, default=Path('/opt/remnanode/docker-compose.yml'))
    args = parser.parse_args()
    try:
        backup = migrate(args.file)
    except (OSError, ValueError) as error:
        parser.exit(1, f'{error}\n')
    print(f'Updated {args.file}; backup: {backup}' if backup else 'Already using the Rust node and core; no changes')
    print(f'Image: {IMAGE}\nXRAY_BINARY={CORE}')
    print('Next: cd ' + shlex.quote(str(args.file.resolve().parent)))
    command = 'docker compose -f ' + shlex.quote(str(args.file.resolve()))
    print(command + ' pull')
    print(command + ' up -d')
    print('Finally restart this node from the Remnawave panel.')


if __name__ == '__main__':
    main()
