#!/usr/bin/env python3
"""Classify DNS literals in every tracked text file and new text file.

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

LITERAL = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|`(?:\\.|[^`\\])*`')
DNS = re.compile(r'(?iu)(?<![\w.-])(?:[a-z0-9\u0080-\uffff](?:[a-z0-9\u0080-\uffff-]{0,61}[a-z0-9\u0080-\uffff])?\.)+[a-z0-9\u0080-\uffff-]{2,63}(?![\w.-])')
URL = re.compile(r'(?i)[a-z][a-z0-9+.-]*://[^\s"\'`<>]+')
TLDS = None


def text_encoding(data):
    """Identify text from its bytes, including Unicode files with a BOM."""
    if data.startswith((b'\xff\xfe\x00\x00', b'\x00\x00\xfe\xff')):
        try:
            data.decode('utf-32')
            return 'utf-32'
        except UnicodeError:
            return None
    if data.startswith((b'\xff\xfe', b'\xfe\xff')):
        try:
            data.decode('utf-16')
            return 'utf-16'
        except UnicodeError:
            return None
    if b'\0' in data:
        return None
    controls = sum(byte < 32 and byte not in (9, 10, 12, 13) for byte in data)
    return 'utf-8' if controls * 100 <= len(data) else None


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
            parsed = urlsplit(match.group())
            host = canonical(parsed.hostname or '') if parsed.scheme.lower() != 'file' else None
        except ValueError:
            host = None
        if host:
            hosts.add(host)
    # Search the whole text, including unquoted attributes, CSS, assignments,
    # Makefiles and comments. A filename-like suffix can also be a real TLD,
    # so any exception belongs in the reviewed allowlist.
    for match in DNS.finditer(value):
        host = canonical(match.group())
        if host and host.rsplit('.', 1)[-1] in TLDS:
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
        if not name:
            continue
        path = root / name
        if not path.is_file() or path.is_symlink():
            continue
        data = path.read_bytes()
        encoding = text_encoding(data)
        if encoding is None:
            continue
        scanned += 1
        source = data.decode(encoding, errors='replace')
        tokens = []
        offset = 0
        for number, line in enumerate(source.split('\n'), 1):
            for match in LITERAL.finditer(line):
                tokens.append((offset + match.start(), offset + match.end(), match.group()[1:-1], number))
            for host in hosts_in(line):
                found.setdefault(host, []).append(f'{name}:{number}')
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
    # Allowlist entries are scanned too; they do not justify themselves.
    for host in sorted(allowed):
        locations = found.get(host, [])
        if any(not location.startswith('testdata/domain-host-allowlist.json:') for location in locations):
            continue
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
