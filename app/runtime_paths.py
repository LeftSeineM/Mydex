"""Portable paths. No user-specific install directories are shipped."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def configured_path(kind, suffix=''):
    defaults = {
        'runtime': ROOT / '.runtime',
        'build': ROOT / '.build',
        'minhook': ROOT / 'vendor' / 'minhook',
        'client': ROOT / '.runtime' / 'unconfigured-client' / 'Weixin.dll',
        'client_exe': ROOT / '.runtime' / 'unconfigured-client' / 'Weixin.exe',
        'gcc': 'gcc',
        'objdump': 'objdump',
    }
    variables = {'runtime':'MYDEX_RUNTIME_DIR','build':'MYDEX_BUILD_DIR',
                 'minhook':'MYDEX_MINHOOK_DIR','client':'MYDEX_WECHAT_DLL',
                 'client_exe':'MYDEX_WECHAT_EXE','gcc':'MYDEX_GCC','objdump':'MYDEX_OBJDUMP'}
    base = os.environ.get(variables[kind]) or defaults[kind]
    return str(Path(base) / suffix) if suffix else str(base)
