"""CurrentUser DPAPI storage bound to an explicit model API base URL."""
import json
from pathlib import Path
from urllib.parse import urlsplit
from research.history_crypto import dpapi

def normalize_base(base):
    parsed=urlsplit(base.strip().rstrip('/'))
    if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError('Protected API credential requires a plain HTTPS base URL')
    return parsed.geturl()

def save_key(path, base, key):
    base=normalize_base(base)
    if not isinstance(key,str) or not key or any(c.isspace() for c in key):
        raise ValueError('Invalid API credential format')
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    encoded=dpapi(json.dumps({'base':base,'key':key}).encode('utf-8'))
    temporary=path.with_suffix('.tmp');temporary.write_bytes(encoded);temporary.replace(path)

def load_key(path, base):
    value=json.loads(dpapi(Path(path).read_bytes(),True))
    if value.get('base')!=normalize_base(base):
        raise ValueError('Credential belongs to another API endpoint')
    return value['key']
