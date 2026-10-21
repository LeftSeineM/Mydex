. (Join-Path $PSScriptRoot 'Paths.ps1')
$ErrorActionPreference='Stop'
& $py -B (Join-Path $PSScriptRoot 'manage.py') stop
