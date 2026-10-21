$bundle=Split-Path -Parent $PSScriptRoot
$runtime=if($env:MYDEX_RUNTIME_DIR){$env:MYDEX_RUNTIME_DIR}else{Join-Path $bundle '.runtime'}
$py=Join-Path $runtime 'venv\Scripts\python.exe'
