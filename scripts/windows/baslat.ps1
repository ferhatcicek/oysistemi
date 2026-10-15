# OySistemi sunucusunu başlatır.
#   powershell -ExecutionPolicy Bypass -File scripts\windows\baslat.ps1 -VeriKlasoru C:\OySistemi
#
# -YerelTest: HTTPS olmadan yalnızca bu bilgisayardan denemek için (çerezlerde Secure kapalı).
param(
    [string]$VeriKlasoru = "C:\OySistemi",
    [int]$Port = 8000,
    [switch]$YerelTest
)
$ErrorActionPreference = "Stop"
$Proje = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$VPy = Join-Path $Proje ".venv\Scripts\python.exe"
if (-not (Test-Path $VPy)) { throw "Önce kurulum.ps1 çalıştırın." }

$argsList = @("-m", "oysistemi.cli", "--home", $VeriKlasoru, "serve", "--host", "127.0.0.1",
              "--port", "$Port")
if ($YerelTest) { $argsList += "--insecure-http" }

Set-Location $Proje
& $VPy @argsList
exit $LASTEXITCODE
