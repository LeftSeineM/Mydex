"""Build the native text-wrapper shim with the existing compiler, in the configured runtime directory."""
from pathlib import Path as _MydexPath
import sys as _mydex_sys
_mydex_sys.path.insert(0, str(next(p for p in _MydexPath(__file__).resolve().parents if (p / 'app/runtime_paths.py').is_file()) / 'app'))
from runtime_paths import configured_path
import hashlib,json,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
OUT=Path(configured_path('runtime', 'research-tools/native-sender'));OUT.mkdir(parents=True,exist_ok=True)
GCC=configured_path('gcc', '')
for source,name,extra in [('native_sender.c','wx-native-sender-v1.dll',['-shared']),('send_fixture.c','wx-send-fixture.exe',[])]:
    result=subprocess.run([GCC,'-O2','-Wall','-Wextra','-Werror','-static-libgcc',*extra,str(HERE/source),'-o',str(OUT/name)],capture_output=True,text=True,timeout=60)
    if result.returncode:raise RuntimeError(result.stderr)
report={'artifacts':{name:hashlib.sha256((OUT/name).read_bytes()).hexdigest() for name in ('wx-native-sender-v1.dll','wx-send-fixture.exe')},
        'sources':{name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in ('native_sender.c','native_sender.h','send_fixture.c')},
        'client_delivery_verified':False}
(OUT/'build.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report))
