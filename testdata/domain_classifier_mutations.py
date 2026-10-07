#!/usr/bin/env python3
"""Named positive and mutation controls for the shared text classifier.

Run from the repository root. Temporary source plants are always removed.
"""
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
HOST = 'fresh-root' + chr(46) + 'site'
OTHER = 'reviewer-crest' + chr(46) + 'site'
FILELIKE = 'fresh-root' + chr(46) + 'zip'


def classify():
    return subprocess.run([sys.executable, str(ROOT / 'domain_literal_classifier.py')],
                          cwd=ROOT, capture_output=True, text=True)


def tracked_types():
    names = [name for name in subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).decode().split('\0')
             if name and (ROOT / name).is_file() and not (ROOT / name).is_symlink()]
    groups = {
        'scss': [name for name in names if name.endswith('.scss')],
        'html': [name for name in names if name.endswith('.html')],
        'makefile': [name for name in names if Path(name).name == 'Makefile'],
        'shell': [name for name in names if name.endswith(('.sh', '.bash'))],
    }
    chosen = {}
    for kind, files in groups.items():
        preferred = [name for name in files if not any(part in name.lower().split('/')
                     for part in ('test', 'tests', 'testdata', 'vendor', 'node_modules', 'docs', 'fixtures', 'deps', 'third_party'))]
        candidates = preferred or files
        if kind == 'scss' and 'shell/client/styles/_install.scss' in files:
            chosen[kind] = ROOT / 'shell/client/styles/_install.scss'
        elif kind == 'html' and str(ROOT).endswith('/shell'):
            production = [name for name in files if name.startswith('shell/imports/client/')]
            chosen[kind] = ROOT / production[0] if production else ROOT / candidates[0]
        elif kind == 'makefile' and 'Makefile' in files:
            chosen[kind] = ROOT / 'Makefile'
        else:
            chosen[kind] = ROOT / candidates[0] if candidates else None
    return chosen


CASES = (
    ('SCSS universal-selector quoted url', 'scss', 'domain-sweep3-mutation.scss', lambda: f'* {{ background: url("https://{HOST}/"); }}\n', HOST),
    ('SCSS unquoted url', 'scss', 'domain-sweep3-mutation.scss', lambda: f'.card {{ background: url(https://{HOST}/pixel); }}\n', HOST),
    ('HTML unquoted src', 'html', 'domain-sweep3-mutation.html', lambda: f'<img src=https://{HOST}/pixel>\n', HOST),
    ('HTML quoted src', 'html', 'domain-sweep3-mutation.html', lambda: f'<img src="https://{HOST}/pixel">\n', HOST),
    ('Makefile URL assignment', 'makefile', 'domain-sweep3-mutation.mk', lambda: f'QA_BASE_URL=https://{OTHER}/\n', OTHER),
    ('Makefile comment URL', 'makefile', 'domain-sweep3-mutation.mk', lambda: f'# QA endpoint https://{HOST}/\n', HOST),
    ('shell URL assignment', 'shell', 'domain-sweep3-mutation.sh', lambda: f'ESTATE_URL=https://{HOST}/\n', HOST),
    ('shell comment URL', 'shell', 'domain-sweep3-mutation.sh', lambda: f'# install endpoint https://{HOST}/\n', HOST),
)


def main():
    result = classify()
    if result.returncode:
        raise AssertionError('DOMAIN_CLASSIFIER_POSITIVE_FAILED:' + result.stderr[-1000:])
    print('DOMAIN_CLASSIFIER_POSITIVE_PASS')
    probe = ROOT / 'domain-sweep3-binary.probe'
    if probe.exists():
        raise AssertionError('DOMAIN_CLASSIFIER_MUTATION_PATH_OCCUPIED:binary')
    try:
        probe.write_bytes(b'\0' + f'https://{HOST}/'.encode())
        if classify().returncode:
            raise AssertionError('DOMAIN_CLASSIFIER_BINARY_DETECTION_FAILED')
        print('DOMAIN_CLASSIFIER_BINARY_SKIPPED')
        probe.write_text(f'https://{HOST}/\n')
        result = classify()
        marker = 'DOMAIN_CLASSIFIER_UNREVIEWED_HOST:' + HOST
        if result.returncode == 0 or marker not in result.stderr:
            raise AssertionError('UNKNOWN_EXTENSION_URL: expected ' + marker)
        print('UNKNOWN_EXTENSION_URL: ' + marker)
        probe.write_text(HOST + '\n')
        result = classify()
        if result.returncode == 0 or marker not in result.stderr:
            raise AssertionError('BARE_HOST_UNKNOWN_EXTENSION: expected ' + marker)
        print('BARE_HOST_UNKNOWN_EXTENSION: ' + marker)
        probe.write_text(FILELIKE + '\n')
        result = classify()
        marker = 'DOMAIN_CLASSIFIER_UNREVIEWED_HOST:' + FILELIKE
        if result.returncode == 0 or marker not in result.stderr:
            raise AssertionError('BARE_HOST_FILENAME_TLD: expected ' + marker)
        print('BARE_HOST_FILENAME_TLD: ' + marker)
        for label, encoding in (('UTF16_HTML_URL', 'utf-16'), ('UTF32_HTML_URL', 'utf-32')):
            probe.write_bytes(f'<img src=https://{HOST}/pixel>\n'.encode(encoding))
            result = classify()
            marker = 'DOMAIN_CLASSIFIER_UNREVIEWED_HOST:' + HOST
            if result.returncode == 0 or marker not in result.stderr:
                raise AssertionError(label + ': expected ' + marker)
            print(label + ': ' + marker)
    finally:
        probe.unlink(missing_ok=True)
    available = tracked_types()
    for name, kind, filename, plant, host in CASES:
        path = available[kind]
        if path is None:
            continue
        original = path.read_bytes()
        try:
            path.write_bytes(original + b'\n' + plant().encode())
            result = classify()
            marker = 'DOMAIN_CLASSIFIER_UNREVIEWED_HOST:' + host
            if result.returncode == 0 or marker not in result.stderr:
                raise AssertionError(name + ': expected ' + marker + ', got ' + result.stderr[-1000:])
            print(name + ': ' + marker)
        finally:
            path.write_bytes(original)
    return 0


if __name__ == '__main__':
    sys.exit(main())
