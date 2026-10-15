# Bilgisayar açıldığında OySistemi'ni otomatik başlatan ve her gece şifreli yedek alan
# Zamanlanmış Görevleri kaydeder. Yönetici olarak çalıştırın.
#
#   powershell -ExecutionPolicy Bypass -File scripts\windows\otomatik-baslat.ps1 `
#       -VeriKlasoru C:\OySistemi -YedekKlasoru D:\OySistemiYedek
#
# Görevler, kurulumu yapan hesapla ve "oturum açılmamış olsa da" çalışır. Windows bunun için
# hesabın parolasını ister. DPAPI ile korunan ana anahtar yalnızca bu hesapla açılabildiği için
# başka bir hesap (ör. SYSTEM) kullanılamaz.
param(
    [string]$VeriKlasoru = "C:\OySistemi",
    [string]$YedekKlasoru = "",
    [int]$Port = 8000
)
$ErrorActionPreference = "Stop"
$Proje = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$VPy = Join-Path $Proje ".venv\Scripts\python.exe"
if (-not (Test-Path $VPy)) { throw "Önce kurulum.ps1 çalıştırın." }

$cred = Get-Credential -UserName "$env:USERDOMAIN\$env:USERNAME" `
    -Message "OySistemi görevlerini çalıştıracak hesabın parolası (anahtar bu hesaba bağlı)"

$ayar = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)

# 1) Sunucu: açılışta başla, çökerse yeniden başlat
$sunucu = New-ScheduledTaskAction -Execute $VPy -WorkingDirectory $Proje `
    -Argument "-m oysistemi.cli --home `"$VeriKlasoru`" serve --host 127.0.0.1 --port $Port"
Register-ScheduledTask -TaskName "OySistemi Sunucu" -Action $sunucu -Settings $ayar -Force `
    -Trigger (New-ScheduledTaskTrigger -AtStartup) `
    -User $cred.UserName -Password $cred.GetNetworkCredential().Password -RunLevel Limited | Out-Null
Write-Host "Görev kaydedildi: OySistemi Sunucu (açılışta)" -ForegroundColor Green

# 2) Kapanış yedeği: sunucu kapalı olsa bile bitiş zamanı gelen oylamalar kapansın
$tick = New-ScheduledTaskAction -Execute $VPy -WorkingDirectory $Proje `
    -Argument "-m oysistemi.cli --home `"$VeriKlasoru`" tick"
$her = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName "OySistemi Kapanis" -Action $tick -Trigger $her -Force `
    -Settings (New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew) `
    -User $cred.UserName -Password $cred.GetNetworkCredential().Password -RunLevel Limited | Out-Null
Write-Host "Görev kaydedildi: OySistemi Kapanis (dakikada bir)" -ForegroundColor Green

# 3) Gece şifreli yedek (isteğe bağlı)
if ($YedekKlasoru) {
    New-Item -ItemType Directory -Force -Path $YedekKlasoru | Out-Null
    $yp = Read-Host "Yedek parolası (en az 12 karakter; kasada saklayın)" -AsSecureString
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($yp))
    # Parola yalnızca bu hesabın kullanıcı ortam değişkeninde tutulur.
    [Environment]::SetEnvironmentVariable("OYS_BACKUP_PASSPHRASE", $plain, "User")
    $yedek = New-ScheduledTaskAction -Execute $VPy -WorkingDirectory $Proje `
        -Argument "-m oysistemi.cli --home `"$VeriKlasoru`" backup `"$YedekKlasoru\oysistemi-{tarih}.oysbak`""
    Register-ScheduledTask -TaskName "OySistemi Yedek" -Action $yedek -Force `
        -Trigger (New-ScheduledTaskTrigger -Daily -At 03:00) `
        -User $cred.UserName -Password $cred.GetNetworkCredential().Password -RunLevel Limited | Out-Null
    Write-Host "Görev kaydedildi: OySistemi Yedek (her gece 03:00 → $YedekKlasoru)" -ForegroundColor Green
}

Write-Host "Hemen başlatmak için:  Start-ScheduledTask -TaskName 'OySistemi Sunucu'"
