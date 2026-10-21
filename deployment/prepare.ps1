param([Parameter(Mandatory=$true)][string]$Python312, [switch]$Resume)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Paths.ps1')
foreach($relative in @('vendor\python312-win-amd64\lief.pyd','vendor\python312-win-amd64\libLIEF.dll','native\worker-sender-v6\build.json','native\worker-sender-v6\wx-worker-sender-v6.dll','native\worker-sender-v6\wx-send-fixture.exe')) {
    if (-not (Test-Path -LiteralPath (Join-Path $bundle $relative))) { throw ('Source-only distribution: missing '+$relative+'. Read docs/SETUP.md before preparing a live runtime.') }
}
$pythonPath=(Resolve-Path -LiteralPath $Python312).Path
& $pythonPath -c "import sys,struct; assert sys.version_info[:2]==(3,12) and struct.calcsize('P')==8"
if ($LASTEXITCODE -ne 0) { throw 'Python 3.12 x64 required.' }
$venv=Join-Path $runtime 'venv'
if ((Test-Path -LiteralPath $venv) -and -not $Resume) { throw 'Existing environment found; inspect and use -Resume to continue without deleting it.' }
New-Item -ItemType Directory -Force -Path $runtime | Out-Null
$env:TEMP=Join-Path $runtime 'temp'; $env:TMP=$env:TEMP
$env:PIP_CACHE_DIR=Join-Path $runtime 'pip-cache'
New-Item -ItemType Directory -Force -Path $env:TEMP | Out-Null
if (-not (Test-Path -LiteralPath $venv)) { & $pythonPath -m venv $venv }
if ($LASTEXITCODE -ne 0) { throw 'venv creation failed.' }
$py=Join-Path $venv 'Scripts\python.exe'
& $py -m pip install --only-binary=:all: -r (Join-Path $PSScriptRoot 'requirements-runtime.txt')
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
Copy-Item -LiteralPath (Join-Path $bundle 'vendor\python312-win-amd64\lief.pyd') -Destination (Join-Path $venv 'Lib\site-packages\lief.pyd')
Copy-Item -LiteralPath (Join-Path $bundle 'vendor\python312-win-amd64\libLIEF.dll') -Destination (Join-Path $venv 'Lib\site-packages\libLIEF.dll')
& $py -c "import lief; assert lief.__version__.startswith('0.12.3')"
if ($LASTEXITCODE -ne 0) { throw 'Target LIEF compatibility check failed.' }
$native=Join-Path $runtime 'research-tools\worker-sender-v6'
if (Test-Path -LiteralPath $native) { throw 'Existing native artifacts found; compare manifests before replacing.' }
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $native) | Out-Null
Copy-Item -LiteralPath (Join-Path $bundle 'native\worker-sender-v6') -Destination $native -Recurse
New-Item -ItemType Directory -Force -Path (Join-Path $bundle 'app\.local\quote-m-session') | Out-Null
Write-Output 'Dependencies prepared. Read HANDOFF.txt; fresh local WeChat enrollment is required before starting.'
