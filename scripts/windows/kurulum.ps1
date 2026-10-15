# OySistemi — Windows kurulumu
#
# Kullanım (proje klasöründe, normal — yönetici OLMAYAN — PowerShell penceresinde):
#   powershell -ExecutionPolicy Bypass -File scripts\windows\kurulum.ps1 -VeriKlasoru C:\OySistemi
#
# ÖNEMLİ: Kurulumu, sunucuyu ÇALIŞTIRACAK Windows hesabıyla yapın. Ana anahtar DPAPI ile bu
# hesaba ve bu bilgisayara bağlanır; başka bir hesap onu açamaz.

param(
    [string]$VeriKlasoru = "C:\OySistemi",
    [string[]]$Yoneticiler = @()
)
$ErrorActionPreference = "Stop"
$Proje = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $Proje

Write-Host "== OySistemi kurulumu ==" -ForegroundColor Cyan
Write-Host "Proje:        $Proje"
Write-Host "Veri klasörü: $VeriKlasoru"
Write-Host "Windows hesabı: $env:USERDOMAIN\$env:USERNAME (ana anahtar bu hesaba bağlanacak)"

# 1) Python
$py = Get-Command py -ErrorAction SilentlyContinue
if ($py) { $PythonCmd = @("py", "-3") } else { $PythonCmd = @("python") }
$ver = & $PythonCmd[0] $PythonCmd[1..9] -c "import sys; print('%d.%d' % sys.version_info[:2])"
if ([version]$ver -lt [version]"3.12") {
    throw "Python 3.12 veya üstü gerekli (bulunan: $ver). https://www.python.org/downloads/windows/"
}
Write-Host "Python $ver bulundu." -ForegroundColor Green

# 2) Sanal ortam ve bağımlılıklar
if (-not (Test-Path ".venv")) {
    & $PythonCmd[0] $PythonCmd[1..9] -m venv .venv
}
$VPy = Join-Path $Proje ".venv\Scripts\python.exe"
& $VPy -m pip install --quiet --upgrade pip
& $VPy -m pip install --quiet -e .
Write-Host "Bağımlılıklar kuruldu." -ForegroundColor Green

# 3) Kurulum: klasör izinleri kilitlenir, DPAPI korumalı anahtar + kurtarma anahtarı üretilir
if (Test-Path (Join-Path $VeriKlasoru "secrets\master.key")) {
    Write-Host "Mevcut kurulum bulundu; init atlandı." -ForegroundColor Yellow
} else {
    & $VPy -m oysistemi.cli --home $VeriKlasoru init
    if ($LASTEXITCODE -ne 0) { throw "init başarısız" }
}

# 4) İlk yöneticiler (en az iki kişi)
if ($Yoneticiler.Count -lt 2) {
    $girdi = Read-Host "İlk yönetici kullanıcı adları (virgülle, en az 2; atlamak için boş)"
    if ($girdi) { $Yoneticiler = $girdi.Split(",") | ForEach-Object { $_.Trim() } }
}
if ($Yoneticiler.Count -ge 2) {
    $spec = $Yoneticiler | ForEach-Object { "${_}:${_}" }
    & $VPy -m oysistemi.cli --home $VeriKlasoru bootstrap-admins @spec
}

# 5) Son denetim
& $VPy -m oysistemi.cli --home $VeriKlasoru harden
& $VPy -m oysistemi.cli --home $VeriKlasoru verify

Write-Host ""
Write-Host "== Sonraki adımlar ==" -ForegroundColor Cyan
Write-Host "1. $VeriKlasoru\secrets\KURTARMA_ANAHTARI.oyskey dosyasını USB belleğe kopyalayın,"
Write-Host "   kasaya koyun ve sunucudan SİLİN."
Write-Host "2. Başlatmak için:  scripts\windows\baslat.ps1 -VeriKlasoru $VeriKlasoru"
Write-Host "3. Bilgisayar açılınca otomatik başlasın:  scripts\windows\otomatik-baslat.ps1"
Write-Host "4. İnternete açacaksanız önüne HTTPS ters vekil (Caddy) koyun — README'ye bakın."
