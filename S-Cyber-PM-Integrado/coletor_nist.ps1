# ==============================================================================
#  S-Cyber NIST Intelligence - coletor avulso (SOMENTE LEITURA)
# ------------------------------------------------------------------------------
#  Para computadores SEM o S-Cyber PM instalado. Faz as mesmas consultas da
#  aba "Coleta tecnica", nao altera nada no Windows e grava um arquivo
#  coleta_<COMPUTADOR>_<data>.json na mesma pasta deste script.
#
#  Como usar: clique duas vezes em coletar_nist_windows.bat (ou rode
#    powershell -NoProfile -ExecutionPolicy Bypass -File coletor_nist.ps1)
#  Como Administrador a coleta fica completa (BitLocker, SMB, Secure Boot).
#  Leve o .json ao computador com o S-Cyber PM e use
#    NIST > Coleta tecnica > Importar coleta de outro computador.
#
#  ARQUIVO GERADO PELO APLICATIVO (collector.standalone_script): nao edite.
# ==============================================================================
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$r = [ordered]@{}
function T($k, [scriptblock]$b) { try { $r[$k] = & $b } catch { $r[$k] = @{ erro = $_.Exception.Message } } }
T meta { $id=[Security.Principal.WindowsIdentity]::GetCurrent()
  @{ host=$env:COMPUTERNAME; user=$id.Name
     admin=([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } }
T os { $o=Get-CimInstance Win32_OperatingSystem; @{ caption=$o.Caption; version=$o.Version; build=$o.BuildNumber;
  lastboot=$o.LastBootUpTime.ToString('s') } }
T defender { $m=Get-MpComputerStatus; @{ realtime=$m.RealTimeProtectionEnabled; service=$m.AMServiceEnabled;
  tamper=$m.IsTamperProtected; sigage=$m.AntivirusSignatureAge; behavior=$m.BehaviorMonitorEnabled } }
T av { @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct |
  ForEach-Object { @{ name=$_.displayName; state=$_.productState } }) }
T firewall { @(Get-NetFirewallProfile | ForEach-Object { @{ name=$_.Name; enabled=[bool]$_.Enabled } }) }
T uac { $p=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
  @{ lua=$p.EnableLUA; admin_prompt=$p.ConsentPromptBehaviorAdmin; inactivity=$p.InactivityTimeoutSecs } }
T rdp { $t=Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server'
  $n=Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
  @{ deny=$t.fDenyTSConnections; nla=$n.UserAuthentication } }
T smb1 { @{ enabled=(Get-SmbServerConfiguration).EnableSMB1Protocol } }
T bitlocker { $v=Get-CimInstance -Namespace root/cimv2/Security/MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume |
  Where-Object DriveLetter -eq $env:SystemDrive; @{ drive=$env:SystemDrive; protection=$v.ProtectionStatus } }
T secureboot { @{ enabled=(Confirm-SecureBootUEFI) } }
T hotfix { $h=Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1
  @{ last=$(if ($h) { $h.InstalledOn.ToString('yyyy-MM-dd') } else { '' }); id=$h.HotFixID } }
T admins { @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { $_.Name }) }
T guest { $g=Get-LocalUser | Where-Object { $_.SID -like '*-501' }; @{ enabled=[bool]$g.Enabled } }
T nopwd { @(Get-LocalUser | Where-Object { $_.Enabled -and -not $_.PasswordRequired } | ForEach-Object { $_.Name }) }
T netaccounts { @(net accounts) }
T screensaver { $d=Get-ItemProperty 'HKCU:\Control Panel\Desktop'
  @{ active=$d.ScreenSaveActive; secure=$d.ScreenSaverIsSecure; timeout=$d.ScreenSaveTimeOut } }
T pslog { $k='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
  @{ enabled=$(if (Test-Path $k) { (Get-ItemProperty $k).EnableScriptBlockLogging } else { 0 }) } }
T eventlog { @{ status=(Get-Service EventLog).Status.ToString() } }
T smartscreen { $p='HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
  $e='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'
  @{ policy=$(if (Test-Path $p) { (Get-ItemProperty $p).EnableSmartScreen } else { $null });
     explorer=(Get-ItemProperty $e).SmartScreenEnabled } }
T restorepoints { @{ count=@(Get-CimInstance -Namespace root/default -ClassName SystemRestore).Count } }
T listening { @(Get-NetTCPConnection -State Listen | Where-Object { $_.LocalAddress -notin '127.0.0.1','::1' } |
  ForEach-Object { $_.LocalPort } | Sort-Object -Unique) }
if ($env:SCYBER_THUMB) { T certificado { $c=Get-Item "Cert:\CurrentUser\My\$env:SCYBER_THUMB"
  @{ notafter=$c.NotAfter.ToString('yyyy-MM-dd'); privatekey=$c.HasPrivateKey } } }

# $r e serializado exatamente como na coleta do aplicativo: aninhar $r em outro objeto antes do
# ConvertTo-Json faz o PowerShell 5.1 gravar listas como {"value":[...],"Count":n}.
$dados = $r | ConvertTo-Json -Depth 5 -Compress
$saida = '{"formato":"scyber-nist-coleta","versao":1,"gerado":"' + (Get-Date).ToString('s') + '","dados":' + $dados + '}'
$pasta = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$arquivo = Join-Path $pasta ('coleta_{0}_{1}.json' -f $env:COMPUTERNAME, (Get-Date).ToString('yyyyMMdd_HHmm'))
[IO.File]::WriteAllText($arquivo, $saida, [Text.UTF8Encoding]::new($false))
Write-Host ''
Write-Host "Coleta gravada em: $arquivo"
Write-Host 'Leve este arquivo ao computador com o S-Cyber PM (Coleta tecnica > Importar).'
