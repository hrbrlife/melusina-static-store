#!/usr/bin/env python3
"""Guard the production paths with the estate sweep's hostname search."""
from pathlib import Path
import collections, hashlib, json, re, subprocess, sys
ROOT=Path(__file__).resolve().parent.parent
HOST=re.compile(r"bazaar[.]melusina-os[.]org|melusina-os[.]org|paype[.]cc|hrbr[.]life|[A-Za-z0-9_-]+([.][A-Za-z0-9_-]+)*[.]example")
HOME=re.compile(r'[/]home[/]user[/]')
EXCLUDED=re.compile(r"(^|/)(test|tests|testdata|fleet|fixtures|docs|documentation|examples|vendor|node_modules|[.]github|release|reports|archive|migrations|generated|packages|third_party|upstream|dev-publish-keys|e2e|qa|domains|[.]iter-artifacts)(/|$)|(_test[.]go|[.]test[.](js|mjs|cjs|ts)|[.]spec[.]ts|[.](md|lock|sum|svg|png|jpg|spk|map))$",re.I)
EXT={'.go','.js','.mjs','.cjs','.ts','.tsx','.jsx','.rs','.py','.sh','.bash','.html','.css','.json','.yaml','.yml','.toml','.conf','.service','.env','.xml','.capnp'}
PACKAGING={'RUNTIME-CONTRACT.json','metadata.json','license_registry.json','Makefile','publish.sh','sandstorm-pkgdef.capnp'}
ALLOW=ROOT/'testdata/domain-literal-allowlist.json'
def key(f,lit,line): return f,lit.lower(),hashlib.sha256(line.strip().encode()).hexdigest()
def main():
 entries=json.loads(ALLOW.read_text())['entries']
 expected={}
 for item in entries:
  k=(item['file'],item['literal'],item['lineSha256'])
  if k in expected or not item.get('reason') or type(item.get('count')) is not int or item['count']<1:
   raise SystemExit('DOMAIN_LITERAL_ALLOWLIST_INVALID')
  expected[k]=item['count']
 seen=collections.Counter(); failures=[]; scanned=0
 names=subprocess.check_output(['git','ls-files','-z','--cached','--others','--exclude-standard'],cwd=ROOT).decode().split('\0')
 for file in sorted(set(names)):
  if not file or file in {'scripts/test-domain-literals.py','testdata/domain-literal-allowlist.json'}: continue
  path=ROOT/file
  if path.is_symlink() or not path.is_file() or (path.suffix not in EXT and file!='testdata/domain-literal-positive.txt'): continue
  raw=path.read_bytes()
  if b'\0' in raw: continue
  excluded=bool(EXCLUDED.search(file) or Path(file).name.startswith('test-') or file in PACKAGING or file=='pkg/seed/demo.go' or file=='internal/testvector/vectors.go')
  machine_scope=(file.startswith(('test/','tests/','testdata/','fixtures/','qa/','e2e/','scripts/')) or file.endswith(('_test.go','.test.js','.test.mjs','.sh','.bash')))
  if not excluded: scanned+=1
  for number,line in enumerate(raw.decode(errors='replace').splitlines(),1):
   for hit in HOST.finditer(line):
    k=key(file,hit.group(),line)
    if k in expected: seen[k]+=1
    elif not excluded: failures.append(f'DOMAIN_LITERAL_FIXED_HOST:{file}:{number}:{hit.group()}')
   if machine_scope:
    for hit in HOME.finditer(line):
     k=key(file,hit.group(),line)
     if k in expected: seen[k]+=1
     else: failures.append(f'DOMAIN_LITERAL_ABSOLUTE_HOME:{file}:{number}:{hit.group()}')
 if not scanned: failures.append('DOMAIN_LITERAL_SCAN_EMPTY')
 for k,n in expected.items():
  if seen[k]!=n: failures.append(f'DOMAIN_LITERAL_ALLOWLIST_STALE:{k[0]}:{k[1]}:expected={n}:seen={seen[k]}')
 if failures:
  print('\n'.join(failures),file=sys.stderr); return 1
 print(f'DOMAIN_LITERAL_GUARD_OK files={scanned} reviewed={len(expected)}')
 return 0
if __name__=='__main__': sys.exit(main())
