"""Build the shipped observer sources with an isolated portable compiler."""
from pathlib import Path as _MydexPath
import sys as _mydex_sys
_mydex_sys.path.insert(0, str(next(p for p in _MydexPath(__file__).resolve().parents if (p / 'app/runtime_paths.py').is_file()) / 'app'))
from runtime_paths import configured_path
import hashlib
import json
import os
from pathlib import Path
import subprocess

BUNDLE = Path(__file__).resolve().parents[1]
HERE = BUNDLE / 'app/research'
DEP = BUNDLE / 'vendor/minhook'
OUT = Path(configured_path('runtime', 'research-tools/native-key-observer'))
COMPILER = Path(configured_path('build', 'ziglang/zig.exe'))


def main():
    original = json.loads((BUNDLE / 'docs/source-manifest.json').read_text(encoding='utf-8'))['files']
    source_names = ['native_key_observer.c', 'native_key_observer.h', 'key_fixture.c']
    selected = [HERE / n for n in source_names] + [p for p in DEP.rglob('*') if p.is_file()]
    for path in selected:
        relative = path.relative_to(BUNDLE).as_posix()
        if original.get(relative) != hashlib.sha256(path.read_bytes()).hexdigest():
            raise ValueError('Bundled observer dependency changed: ' + relative)
    OUT.mkdir(parents=True, exist_ok=True)
    if (OUT / 'build.json').exists():
        raise ValueError('Build already exists; inspect before replacing')
    environment = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=configured_path('build', 'cache'),
                       ZIG_LOCAL_CACHE_DIR=configured_path('build', 'local-cache'))
    sources = [DEP / 'src' / n for n in ['hook.c', 'buffer.c', 'trampoline.c', 'hde/hde64.c']]
    common = [str(COMPILER), 'cc', '-target', 'x86_64-windows-gnu', '-U_WIN32_WINNT', '-D_WIN32_WINNT=0x0600',
              '-O2', '-Wall', '-Wextra', '-Werror']
    commands = [[*common, '-shared', '-I' + str(DEP / 'include'), *map(str, sources),
                 str(HERE / 'native_key_observer.c'), '-o', str(OUT / 'wx-native-key-observer-v1.dll')],
                [*common, str(HERE / 'key_fixture.c'), '-o', str(OUT / 'wx-key-fixture.exe')]]
    for command in commands:
        subprocess.run(command, env=environment, check=True, timeout=240)
    manifest = {'compiler': 'zig 0.13.0 cc x86_64-windows-gnu', 'target_rva': '0x58325d0',
                'client_execution_verified': False,
                'artifacts': {name: hashlib.sha256((OUT / name).read_bytes()).hexdigest()
                              for name in ('wx-native-key-observer-v1.dll', 'wx-key-fixture.exe')},
                'sources': {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                            for p in sources + [HERE / n for n in source_names]}}
    (OUT / 'build.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    print('Observer built from manifest-verified sources. Fixture still required.')


if __name__ == '__main__':
    main()
