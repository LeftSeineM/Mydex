"""Build the independently versioned, passive database-key observer in the configured build directory."""
from pathlib import Path as _MydexPath
import sys as _mydex_sys
_mydex_sys.path.insert(0, str(next(p for p in _MydexPath(__file__).resolve().parents if (p / 'app/runtime_paths.py').is_file()) / 'app'))
from runtime_paths import configured_path
import hashlib,json,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
DEP=Path(configured_path('minhook', ''))
OUT=Path(configured_path('runtime', 'research-tools/native-key-observer'))
COMMIT='c3fcafdc10146beb5919319d0683e44e3c30d537'
GCC=Path(configured_path('gcc', ''))
def run(args):
    result=subprocess.run([str(a) for a in args],capture_output=True,text=True,timeout=90)
    if result.returncode:raise RuntimeError(result.stderr or result.stdout)
    return result
if run(['git','-C',DEP,'rev-parse','HEAD']).stdout.strip()!=COMMIT or run(['git','-C',DEP,'status','--porcelain']).stdout.strip():raise ValueError('Dependency changed')
OUT.mkdir(parents=True,exist_ok=True)
sources=[DEP/'src'/n for n in ['hook.c','buffer.c','trampoline.c','hde/hde64.c']]
common=[GCC,'-O2','-Wall','-Wextra','-Werror','-static-libgcc']
run([*common,'-shared','-I'+str(DEP/'include'),*sources,HERE/'native_key_observer.c','-o',OUT/'wx-native-key-observer-v1.dll'])
run([*common,HERE/'key_fixture.c','-o',OUT/'wx-key-fixture.exe'])
manifest={'commit':COMMIT,'target_rva':'0x58325d0','client_execution_verified':False,
          'artifacts':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in [OUT/'wx-native-key-observer-v1.dll',OUT/'wx-key-fixture.exe']},
          'sources':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sources+[HERE/'native_key_observer.c',HERE/'native_key_observer.h',HERE/'key_fixture.c']}}
(OUT/'build.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8');print(json.dumps(manifest))
