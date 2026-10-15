# OySistemi — Windows kurulumu
#
# Kullanım (proje klasöründe, normal — yönetici OLMAYAN — PowerShell penceresinde):
#   powershell -ExecutionPolicy Bypass -File scripts\windows\kurulum.ps1 -VeriKlasoru C:\OySistemi
#
# ÖNEMLİ: Kurulumu, sunucuyu ÇALIŞTIRACAK Windows hesabıyla yapın. Ana anahtar DPAPI ile bu
# hesaba ve bu bilgisayara bağlanır; başka bir hesap onu açamaz.
#
# Seçenekler:
#   -Python "C:\Python313\python.exe"   Belirli bir Python kullan (otomatik seçim yerine)
#   -KurtarmaParolasiDegiskeni AD       Kurtarma parolasını bu ortam değişkeninden al (otomasyon/CI)
#   -YoneticiKurulumunuAtla             İlk yöneticileri sorma (sonra bootstrap-admins ile)

param(
    [string]$VeriKlasoru = "C:\OySistemi",
    [string[]]$Yoneticiler = @(),
    [string]$Python = "",
    [string]$KurtarmaParolasiDegiskeni = "",
    [switch]$YoneticiKurulumunuAtla
)
$ErrorActionPreference = "Stop"
$Proje = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $Proje

function Fail([string]$mesaj) {
    Write-Host ""
    Write-Host "HATA: $mesaj" -ForegroundColor Red
    exit 1
}

# Bir Python yorumlayıcısını yoklar. Dönüş: @{Ver; Major; Minor; FreeThreaded; Bits; Path} veya $null.
# Not: Windows PowerShell 5.1'de $ErrorActionPreference=Stop iken yerel komutun stderr'ini
# yönlendirmek sonlandırıcı hata üretir; bu yüzden yoklama "Continue" ile yapılır.
function Get-PythonInfo([string]$exe, [string[]]$pre) {
    $kod = "import sys,sysconfig,struct;print('%d|%d|%s|%d|%s'%(sys.version_info[0]," +
           "sys.version_info[1],sysconfig.get_config_var('Py_GIL_DISABLED') or 0," +
           "struct.calcsize('P')*8,sys.executable))"
    $eski = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $out = & $exe @pre -c $kod 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $out) { return $null }
        $p = ([string]($out | Select-Object -Last 1)).Trim().Split("|")
        if ($p.Count -lt 5) { return $null }
        return @{ Major = [int]$p[0]; Minor = [int]$p[1]; Ver = "$($p[0]).$($p[1])";
                  FreeThreaded = ($p[2] -eq "1"); Bits = [int]$p[3]; Path = $p[4] }
    } catch {
        return $null
    } finally {
        $ErrorActionPreference = $eski
    }
}

function Test-Uygun($info) {
    if (-not $info) { return "çalıştırılamadı" }
    if ($info.Major -ne 3 -or $info.Minor -lt 12) { return "sürüm $($info.Ver) (3.12+ gerekli)" }
    # Free-threaded (GIL'siz, "3.13t") yapı için cryptography/cffi Windows paketleri yok.
    if ($info.FreeThreaded) { return "free-threaded (GIL'siz) deneysel yapı — desteklenmiyor" }
    if ($info.Bits -ne 64) { return "$($info.Bits) bit — 64 bit gerekli" }
    return $null
}

Write-Host "== OySistemi kurulumu ==" -ForegroundColor Cyan
Write-Host "Proje:        $Proje"
Write-Host "Veri klasörü: $VeriKlasoru"
Write-Host "Windows hesabı: $env:USERDOMAIN\$env:USERNAME (ana anahtar bu hesaba bağlanacak)"

# ─── 1) Uygun Python'u bul ───────────────────────────────────────────────────────────────
# "py -3" KULLANILMAZ: bazı kurulumlarda varsayılanı deneysel free-threaded 3.13t'dir.
$adaylar = @()
if ($Python) {
    $adaylar += , @($Python)
} else {
    if (Get-Command py -ErrorAction SilentlyContinue) {
        foreach ($v in "3.14", "3.13", "3.12") { $adaylar += , @("py", "-$v") }
    }
    foreach ($c in "python", "python3") {
        if (Get-Command $c -ErrorAction SilentlyContinue) { $adaylar += , @($c) }
    }
}
$secilen = $null
foreach ($a in $adaylar) {
    $exe = $a[0]
    $pre = @($a | Select-Object -Skip 1)
    $info = Get-PythonInfo $exe $pre
    $neden = Test-Uygun $info
    $ad = ($a -join " ")
    if ($neden) {
        if ($info) { Write-Host "  atlandı: $ad → $neden" -ForegroundColor DarkGray }
        continue
    }
    $secilen = $info
    break
}
if (-not $secilen) {
    Fail ("Uygun Python bulunamadı. Python 3.12+ (64 bit, standart sürüm — 'free-threaded' " +
          "OLMAYAN) kurun: https://www.python.org/downloads/windows/  ya da -Python ile yol verin.")
}
Write-Host "Python $($secilen.Ver) kullanılacak: $($secilen.Path)" -ForegroundColor Green

# ─── 2) Sanal ortam ──────────────────────────────────────────────────────────────────────
$VPy = Join-Path $Proje ".venv\Scripts\python.exe"
if (Test-Path ".venv") {
    $neden = Test-Uygun (Get-PythonInfo $VPy @())
    if ($neden) {
        Write-Host "Mevcut .venv kullanılamaz ($neden); yeniden oluşturuluyor." -ForegroundColor Yellow
        Remove-Item -Recurse -Force ".venv"
    }
}
if (-not (Test-Path ".venv")) {
    & $secilen.Path -m venv .venv
    if ($LASTEXITCODE -ne 0) { Fail "sanal ortam oluşturulamadı" }
}

# ─── 3) Bağımlılıklar ────────────────────────────────────────────────────────────────────
& $VPy -m pip install --quiet --disable-pip-version-check --upgrade pip
if ($LASTEXITCODE -ne 0) { Fail "pip güncellenemedi" }
# --prefer-binary: Windows'ta derleyici gerektiren kaynak paketlerden kaçın.
& $VPy -m pip install --quiet --disable-pip-version-check --prefer-binary -e .
if ($LASTEXITCODE -ne 0) {
    Fail "bağımlılıklar kurulamadı (yukarıdaki pip çıktısına bakın; internet/proxy erişimini denetleyin)"
}
& $VPy -c "import cryptography, argon2, fastapi, uvicorn, jinja2, multipart, zoneinfo, oysistemi; zoneinfo.ZoneInfo('Europe/Istanbul')"
if ($LASTEXITCODE -ne 0) { Fail "bağımlılıklar kuruldu ama içe aktarılamıyor" }
Write-Host "Bağımlılıklar kuruldu ve doğrulandı." -ForegroundColor Green

# ─── 4) Kurulum: klasör izinleri, DPAPI korumalı anahtar + kurtarma anahtarı ─────────────
if (Test-Path (Join-Path $VeriKlasoru "secrets\master.key")) {
    Write-Host "Mevcut kurulum bulundu; init atlandı." -ForegroundColor Yellow
} else {
    $initArgs = @("-m", "oysistemi.cli", "--home", $VeriKlasoru, "init")
    if ($KurtarmaParolasiDegiskeni) {
        $initArgs += @("--recovery-passphrase-env", $KurtarmaParolasiDegiskeni)
    }
    & $VPy @initArgs
    if ($LASTEXITCODE -ne 0) { Fail "init başarısız" }
}

# ─── 5) İlk yöneticiler (en az iki kişi) ─────────────────────────────────────────────────
if (-not $YoneticiKurulumunuAtla) {
    if ($Yoneticiler.Count -lt 2) {
        $girdi = Read-Host "İlk yönetici kullanıcı adları (virgülle, en az 2; atlamak için boş)"
        if ($girdi) { $Yoneticiler = $girdi.Split(",") | ForEach-Object { $_.Trim() } }
    }
    if ($Yoneticiler.Count -ge 2) {
        $spec = $Yoneticiler | ForEach-Object { "${_}:${_}" }
        & $VPy -m oysistemi.cli --home $VeriKlasoru bootstrap-admins @spec
        if ($LASTEXITCODE -ne 0) { Fail "yöneticiler oluşturulamadı" }
    }
}

# ─── 6) Son denetim ──────────────────────────────────────────────────────────────────────
& $VPy -m oysistemi.cli --home $VeriKlasoru harden
if ($LASTEXITCODE -ne 0) { Fail "klasör izinleri kilitlenemedi" }
& $VPy -m oysistemi.cli --home $VeriKlasoru verify
if ($LASTEXITCODE -ne 0) { Fail "bütünlük denetiminde kritik bulgu var" }

Write-Host ""
Write-Host "== Kurulum tamam. Sonraki adımlar ==" -ForegroundColor Cyan
Write-Host "1. $VeriKlasoru\secrets\KURTARMA_ANAHTARI.oyskey dosyasını USB belleğe kopyalayın,"
Write-Host "   kasaya koyun ve sunucudan SİLİN."
Write-Host "2. Başlatmak için:  scripts\windows\baslat.ps1 -VeriKlasoru $VeriKlasoru"
Write-Host "3. Bilgisayar açılınca otomatik başlasın:  scripts\windows\otomatik-baslat.ps1"
Write-Host "4. İnternete açacaksanız önüne HTTPS ters vekil (Caddy) koyun — README'ye bakın."
exit 0
