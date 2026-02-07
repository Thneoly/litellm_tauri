#!/usr/bin/env pwsh
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$rootDir = Resolve-Path (Join-Path $PSScriptRoot "..")
$buildDir = if ($env:BUILD_DIR) { $env:BUILD_DIR } else { Join-Path $env:TEMP "litellm_build_py313" }
$venvDir = if ($env:VENV_DIR) { $env:VENV_DIR } else { Join-Path $buildDir ".venv" }
$cacheDir = if ($env:NUITKA_CACHE_DIR) { $env:NUITKA_CACHE_DIR } else { Join-Path $buildDir "nuitka_cache" }
$outDir = if ($env:OUT_DIR) { $env:OUT_DIR } else { Join-Path $buildDir "out" }
$litellmVersion = if ($env:LITELLM_VERSION) { $env:LITELLM_VERSION } else { "1.81.6" }
$pythonVersion = if ($env:PYTHON_VERSION) { $env:PYTHON_VERSION } else { "3.13" }

New-Item -ItemType Directory -Force -Path $buildDir, $cacheDir, $outDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $rootDir "src-tauri\\bin") | Out-Null

$pythonBin = $null
if (Get-Command uv -ErrorAction SilentlyContinue) {
  uv python install $pythonVersion
  uv venv $venvDir --python $pythonVersion
  $pythonBin = Join-Path $venvDir "Scripts\\python.exe"
  uv pip install --python $pythonBin "litellm[proxy]==$litellmVersion" nuitka zstandard
} else {
  $systemPython = Get-Command python -ErrorAction SilentlyContinue
  if (-not $systemPython) {
    throw "python not found. Install python or uv first."
  }
  & $systemPython.Source -m venv $venvDir
  $pythonBin = Join-Path $venvDir "Scripts\\python.exe"
  & $pythonBin -m pip install --upgrade pip
  & $pythonBin -m pip install "litellm[proxy]==$litellmVersion" nuitka zstandard
}

$serverScript = @'
import os
import sys
from typing import List

import litellm.proxy.proxy_cli as proxy_cli


def _has_flag(args: List[str], flag: str) -> bool:
    for item in args:
        if item == flag or item.startswith(flag + "="):
            return True
    return False


def _inject_arg(args: List[str], flag: str, value: str) -> None:
    if value and not _has_flag(args, flag):
        args.extend([flag, value])


def main() -> None:
    args = list(sys.argv[1:])
    config_path = os.environ.get("LITELLM_CONFIG_PATH")
    port = os.environ.get("LITELLM_PORT")

    if config_path:
        _inject_arg(args, "--config", config_path)
    if port:
        _inject_arg(args, "--port", port)

    proxy_cli.run_server.main(args=args, prog_name="litellm_server")


if __name__ == "__main__":
    main()
'@

$serverPath = Join-Path $buildDir "litellm_server.py"
$serverScript | Set-Content -Path $serverPath -Encoding ASCII

$sitePackages = & $pythonBin -c "import sysconfig; print(sysconfig.get_paths()['purelib'])"
$endpointsJson = Join-Path $sitePackages "litellm\\containers\\endpoints.json"
$swaggerDir = Join-Path $sitePackages "litellm\\proxy\\swagger"

if (-not (Test-Path $endpointsJson)) {
  throw "Missing endpoints.json at $endpointsJson"
}
if (-not (Test-Path $swaggerDir)) {
  throw "Missing swagger dir at $swaggerDir"
}

$env:NUITKA_CACHE_DIR = $cacheDir
& $pythonBin -m nuitka `
  --onefile `
  --static-libpython=no `
  --include-package=litellm `
  --include-package=litellm.litellm_core_utils `
  "--include-data-files=$endpointsJson=litellm/containers/endpoints.json" `
  "--include-data-dir=$swaggerDir=litellm/proxy/swagger" `
  --output-filename=litellm_server `
  --output-dir=$outDir `
  $serverPath

$builtExe = Join-Path $outDir "litellm_server.exe"
$destExe = Join-Path $rootDir "src-tauri\\bin\\litellm_server.exe"
Copy-Item $builtExe $destExe -Force

$targetTriple = & rustc --print host-tuple 2>$null
if (-not $targetTriple) {
  $hostLine = & rustc -Vv | Select-String "^host:"
  if ($hostLine) {
    $targetTriple = $hostLine.ToString() -replace "^host:\\s*", ""
  }
}
$targetTriple = if ($targetTriple) { $targetTriple.Trim() } else { "" }
if (-not $targetTriple) {
  throw "Could not determine Rust target triple."
}

$destTripleExe = Join-Path $rootDir "src-tauri\\bin\\litellm_server-$targetTriple.exe"
Copy-Item $destExe $destTripleExe -Force

Write-Host "Built: $destExe"
