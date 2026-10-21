"""Separate receive build; never overwrites the running outbound observer."""
from pathlib import Path as _MydexPath
import sys as _mydex_sys
_mydex_sys.path.insert(0, str(next(p for p in _MydexPath(__file__).resolve().parents if (p / 'app/runtime_paths.py').is_file()) / 'app'))
from runtime_paths import configured_path
import hashlib
import json
from pathlib import Path
import subprocess
HERE=Path(__file__).resolve().parent
DEPENDENCY=Path(configured_path('minhook', ''))
COMMIT='c3fcafdc10146beb5919319d0683e44e3c30d537'
OUT=Path(configured_path('runtime', 'research-tools/native-receiver'))
GCC=Path(configured_path('gcc', ''))
def run(args):
    result=subprocess.run([str(a) for a in args],capture_output=True,text=True,timeout=90)
    if result.returncode:raise RuntimeError(result.stderr or result.stdout)
    return result
def main():
    if run(['git','-C',DEPENDENCY,'rev-parse','HEAD']).stdout.strip()!=COMMIT:raise ValueError('Unexpected dependency')
    if run(['git','-C',DEPENDENCY,'status','--porcelain']).stdout.strip():raise ValueError('Modified dependency')
    OUT.mkdir(parents=True,exist_ok=True)
    upstream=[DEPENDENCY/'src'/n for n in ['hook.c','buffer.c','trampoline.c','hde/hde64.c']]
    common=[GCC,'-O2','-Wall','-Wextra','-Werror','-static-libgcc']
    run([*common,'-shared','-I'+str(DEPENDENCY/'include'),*upstream,HERE/'native_receiver.c','-o',OUT/'wx-native-receiver-v2.dll'])
    run([*common,HERE/'receive_fixture.c','-o',OUT/'wx-receive-fixture.exe'])
    manifest={'commit':COMMIT,'upstream':'https://github.com/TsudaKageyu/minhook','target_rva':'0x2e7caf0',
              'client_execution_verified':False,
              'artifacts':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in
                           [OUT/'wx-native-receiver-v2.dll',OUT/'wx-receive-fixture.exe']},
              'sources':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in
                         upstream+[HERE/'native_receiver.c',HERE/'native_receiver.h',HERE/'receive_fixture.c']}}
    (OUT/'build.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print(json.dumps(manifest))
if __name__=='__main__':main()
