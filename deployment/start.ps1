$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Paths.ps1')
& $py -B (Join-Path $PSScriptRoot 'manage.py') start
if ($LASTEXITCODE -ne 0) { throw 'Current account, native delivery, and model configuration must be verified first.' }
