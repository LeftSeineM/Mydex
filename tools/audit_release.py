"""Audit source-only release without printing matched secrets or chat data."""
from pathlib import Path
import re,sys
root=Path(__file__).resolve().parents[1]
excluded={'.git','.local','__pycache__','.venv','private'}
patterns=[r'\bsk-[A-Za-z0-9_-]{24,}',r'\bgh[pous]_[A-Za-z0-9]{25,}',r'-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----']
issues=[];count=0
for p in root.rglob('*'):
 if not p.is_file() or any(x in excluded for x in p.relative_to(root).parts):continue
 if p.suffix in {'.db','.sqlite','.sqlite3','.dpapi','.dll','.exe','.pyd','.zip','.bak'}:
  issues.append((str(p.relative_to(root)),'private/runtime/binary file'));continue
 try:s=p.read_text(encoding='utf-8-sig')
 except UnicodeDecodeError:issues.append((str(p.relative_to(root)),'non-text file'));continue
 count+=1
 if any(re.search(pattern,s) for pattern in patterns):issues.append((str(p.relative_to(root)),'credential-like value'))
 for identifier in re.findall(r'\b\d{8,20}@chatroom',s):
  if not identifier.startswith(('9000000','9999999')):issues.append((str(p.relative_to(root)),'non-example group identity'))
 for identifier in re.findall(r'\bwxid_[A-Za-z0-9]{10,}',s):
  if not identifier.startswith('wxid_example'):issues.append((str(p.relative_to(root)),'non-example account identity'))
for path,reason in sorted(set(issues)):print(path+': '+reason)
print(f'Audited {count} text files; {len(set(issues))} findings. This is a heuristic scan, not a proof of absence.')
sys.exit(bool(issues))
