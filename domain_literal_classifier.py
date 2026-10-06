#!/usr/bin/env python3
"""Classify DNS literals in tracked and new production source files.

This file is copied byte-for-byte into each repository. A repo may approve a
non-estate host only in domain-host-allowlist.json, with a reason for the host.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlsplit

SOURCE_EXT = {'.go', '.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.py',
              '.rs', '.sh', '.bash', '.html', '.css', '.json', '.yaml', '.yml',
              '.toml', '.conf', '.service', '.env', '.xml', '.capnp', '.c',
              '.cc', '.cpp', '.h', '.hpp', '.c++', '.h++'}
EXCLUDED_PARTS = {'test', 'tests', 'testdata', 'testvector', 'fixtures', 'fixture', 'vendor',
                  'node_modules', 'third_party', 'upstream', 'generated',
                  '.git', 'docs', 'documentation', 'examples',
                  'archive', 'reports', 'dist', 'fleet',
                  'packages', 'riker-test-deploys', 'deps', 'qa',
                  'e2e', 'dev-publish-keys', '__conformance__',
                  'async-mutations', 'async-codemod', 'test-fixtures',
                  'nft-assets', 'approval-manifests'}
EXCLUDED_NAMES = {'domain_literal_classifier.py', 'domain-host-allowlist.json',
                  'domain-tlds.txt', 'domain-literal-allowlist.json',
                  'home-literal-allowlist.json'}
TEST_NAME = re.compile(r'(?:^test[_-]|[_-]test[.]|[.]test[.]|[.]spec[.]|fixture|(?:^|[-_.])smoke(?:[-_.]|$))', re.I)
LITERAL = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|`(?:\\.|[^`\\])*`')
DNS = re.compile(r'(?iu)(?<![\w.-])(?:[a-z0-9\u0080-\uffff](?:[a-z0-9\u0080-\uffff-]{0,61}[a-z0-9\u0080-\uffff])?\.)+[a-z0-9\u0080-\uffff-]{2,63}(?![\w.-])')
URL = re.compile(r'(?i)https?://[^\s"\'`<>]+')
FILE_SUFFIX = set('ico png svg jpg jpeg gif pdf csv txt zip exe cc c h hpp c++ go rs py js mjs cjs ts tsx jsx css html xml json yaml yml toml sh bash so a lib out pem crt key b58 capnp spk md lock sum proto mk gypi bzl bp cmake gni wasm sha256 ini cfg sql log patch map service env bin target network'.split())
TLDS = None


def is_source(path):
    p = Path(path)
    return (p.suffix.lower() in SOURCE_EXT or p.name in {'Makefile', 'Dockerfile'}) and not (
        set(p.parts) & EXCLUDED_PARTS or p.name in EXCLUDED_NAMES or
        TEST_NAME.search(p.name) or 'staging-grant' in p.name or
        ('ci' in p.parts and p.name.endswith(('-vectors.rs', '-vectors.go'))) or
        any(part.startswith('.native-fixture-producer-') for part in p.parts) or
        any(part.lower().endswith('test') for part in p.parts[:-1]) or
        p.name.endswith(('.min.js', '.map')) or
        '/ui/assets/' in '/' + path)


def canonical(host):
    host = host.rstrip('.').lower()
    try:
        host = host.encode('idna').decode('ascii')
    except UnicodeError:
        return None
    if not DNS.fullmatch(host) or not re.search(r'[a-z]', host.rsplit('.', 1)[-1]):
        return None
    return host


def line_literals(line):
    """Return literal values, including adjacent literals joined by +."""
    tokens = []
    for match in LITERAL.finditer(line):
        raw = match.group()[1:-1]
        # Decode common escapes so an escaped URL is treated as the same host.
        value = raw.replace('\\/', '/').replace('\\u002e', '.').replace('\\x2e', '.')
        tokens.append((match.start(), match.end(), value))
    values = [value for _, _, value in tokens]
    for start in range(len(tokens)):
        value = tokens[start][2]
        for end in range(start + 1, len(tokens)):
            between = line[tokens[end - 1][1]:tokens[end][0]]
            if not re.fullmatch(r'\s*\+\s*', between):
                break
            value += tokens[end][2]
            values.append(value)
    return values


def multiline_literals(source, tokens):
    """Reassemble one quoted expression continued across source lines."""
    for start in range(len(tokens)):
        value = tokens[start][2]
        crossed_line = False
        for end in range(start + 1, min(start + 9, len(tokens))):
            between = source[tokens[end - 1][1]:tokens[end][0]]
            if not re.fullmatch(r'\s*\+\s*', between):
                break
            crossed_line |= '\n' in between
            value += tokens[end][2]
            if crossed_line:
                yield tokens[start][3], value


def hosts_in(value):
    hosts = set()
    for match in URL.finditer(value):
        try:
            host = canonical(urlsplit(match.group()).hostname or '')
        except ValueError:
            host = None
        if host:
            hosts.add(host)
    # A literal containing just a host (optionally with a port or final dot)
    # is also executable input even when it has no URL scheme.
    bare = value.strip().rstrip('.')
    if re.fullmatch(r'[^\s/:]+(?::[0-9]{1,5})?', bare):
        host = canonical(bare.rsplit(':', 1)[0] if ':' in bare else bare)
        if host and host.rsplit('.', 1)[-1] in TLDS and host.rsplit('.', 1)[-1] not in FILE_SUFFIX:
            hosts.add(host)
    return hosts


def inventory(root):
    global TLDS
    TLDS = {line.strip() for line in (root / 'domain-tlds.txt').read_text().splitlines()
            if line.strip() and not line.startswith('#')}
    names = subprocess.check_output(
        ['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'],
        cwd=root).decode().split('\0')
    found = {}
    scanned = 0
    for name in sorted(set(names)):
        if not name or not is_source(name):
            continue
        path = root / name
        if not path.is_file() or path.is_symlink():
            continue
        data = path.read_bytes()
        if b'\0' in data:
            continue
        scanned += 1
        source = data.decode('utf-8', errors='replace')
        tokens = []
        offset = 0
        for number, line in enumerate(source.split('\n'), 1):
            if line.lstrip().startswith(('//', '#', '*')):
                offset += len(line) + 1
                continue
            for match in LITERAL.finditer(line):
                tokens.append((offset + match.start(), offset + match.end(), match.group()[1:-1], number))
            for value in line_literals(line):
                for host in hosts_in(value):
                    found.setdefault(host, []).append(f'{name}:{number}')
            offset += len(line) + 1
        for number, value in multiline_literals(source, tokens):
            for host in hosts_in(value):
                found.setdefault(host, []).append(f'{name}:{number}')
    return scanned, found


def check(root):
    allow_path = root / 'testdata/domain-host-allowlist.json'
    try:
        raw = json.loads(allow_path.read_text())
        entries = raw['hosts']
        if not isinstance(entries, list):
            raise ValueError('hosts must be a list')
        allowed = {}
        for entry in entries:
            host = canonical(entry['host'])
            if host is None or host != entry['host'] or host in allowed or not entry['reason'].strip():
                raise ValueError('invalid, duplicate, or unreasoned host')
            allowed[host] = entry['reason']
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f'DOMAIN_CLASSIFIER_ALLOWLIST_INVALID:{exc}', file=sys.stderr)
        return 1
    scanned, found = inventory(root)
    failures = []
    if not scanned:
        failures.append('DOMAIN_CLASSIFIER_SCAN_EMPTY')
    for host, locations in sorted(found.items()):
        if host not in allowed:
            failures.append(f'DOMAIN_CLASSIFIER_UNREVIEWED_HOST:{host}:{locations[0]}')
    for host in sorted(allowed.keys() - found.keys()):
        failures.append(f'DOMAIN_CLASSIFIER_ALLOWLIST_STALE:{host}')
    if failures:
        print('\n'.join(failures), file=sys.stderr)
        return 1
    print(f'DOMAIN_CLASSIFIER_OK files={scanned} hosts={len(found)}')
    return 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--inventory', action='store_true')
    args = parser.parse_args()
    root = args.root.resolve()
    if args.inventory:
        _, found = inventory(root)
        print(json.dumps(found, indent=2, sort_keys=True))
    else:
        sys.exit(check(root))
