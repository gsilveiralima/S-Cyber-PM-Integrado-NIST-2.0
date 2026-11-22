"""Coleta técnica automática (SOMENTE LEITURA) de evidências deste computador.

Cada verificação consulta o Windows pelo PowerShell, sem alterar nada, e é
ligada às subcategorias do NIST CSF 2.0 que ela evidencia. O resultado
(dados brutos + SHA-256) é gravado como registro da coleta.

Algumas consultas exigem Administrador (BitLocker, SMB, Secure Boot); sem
essa permissão o item aparece como "Indisponível", nunca como falha.

A avaliação (evaluate) é Python puro e testável fora do Windows.
"""
from __future__ import annotations

import base64
import json
import subprocess
import sys

TIMEOUT = 90

# Cada bloco grava em $r.<chave>; erros viram {erro=...} sem interromper os demais.
_PS = r'''
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
$r | ConvertTo-Json -Depth 5 -Compress
'''

RISKY_PORTS = {21: 'FTP', 23: 'Telnet', 135: 'RPC', 139: 'NetBIOS', 445: 'SMB', 3389: 'RDP', 5985: 'WinRM'}


def run(thumbprint=None):
    """Executa o PowerShell e devolve o dict bruto. Só no Windows."""
    if sys.platform != 'win32':
        raise RuntimeError('A coleta técnica só funciona no Windows.')
    import os
    env = dict(os.environ)
    if thumbprint:
        env['SCYBER_THUMB'] = ''.join(ch for ch in thumbprint if ch.isalnum())
    encoded = base64.b64encode(_PS.encode('utf-16-le')).decode('ascii')
    proc = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                           '-EncodedCommand', encoded], capture_output=True, text=True, timeout=TIMEOUT,
                          env=env, encoding='utf-8', errors='replace',
                          creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    out = proc.stdout.strip()
    if not out:
        raise RuntimeError(proc.stderr.strip() or 'O PowerShell não retornou dados.')
    return json.loads(out.splitlines()[-1])


# ------------------------------------------------------------------ avaliação
def _r(id_, title, status, detail, subs):
    return {'id': id_, 'title': title, 'status': status, 'detail': detail, 'subs': subs}


def _err(v):
    return isinstance(v, dict) and 'erro' in v


def _unavailable(id_, title, value, subs):
    msg = value.get('erro', 'sem dados') if isinstance(value, dict) else 'sem dados'
    return _r(id_, title, 'Indisponível', f'Não foi possível consultar ({msg[:160]}).', subs)


def _as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _net_accounts(lines):
    """Extrai números do 'net accounts' pela posição (o texto muda com o idioma).
    Ordem: logoff, idade mín., idade máx., comprimento mín., histórico, limite de bloqueio, ..."""
    values = []
    for line in _as_list(lines):
        if ':' not in str(line):
            continue
        tail = str(line).rsplit(':', 1)[1].strip()
        digits = ''.join(ch for ch in tail if ch.isdigit())
        values.append(int(digits) if digits else None)
    if len(values) < 6:
        return None
    return {'min_length': values[3], 'history': values[4], 'lockout': values[5]}


def evaluate(raw, today=None):
    """Transforma o dict bruto em verificações com situação OK/Atenção/Falha/Indisponível."""
    from datetime import date
    today = today or date.today()
    out = []

    v = raw.get('defender')
    subs = ['DE.CM-09', 'PR.PS-05']
    if _err(v) or not v:
        av = [a.get('name') for a in _as_list(raw.get('av')) if isinstance(a, dict)]
        out.append(_r('defender', 'Antivírus / Microsoft Defender', 'Atenção' if av else 'Indisponível',
                      f'Defender não consultado; antivírus registrado: {", ".join(av) or "nenhum"}.', subs))
    else:
        problems = []
        if not v.get('realtime'):
            problems.append('proteção em tempo real DESLIGADA')
        if not v.get('service'):
            problems.append('serviço antimalware parado')
        age = v.get('sigage')
        if isinstance(age, int) and age > 7:
            problems.append(f'assinaturas com {age} dias')
        if v.get('tamper') is False:
            problems.append('proteção contra adulteração desligada')
        status = 'Falha' if (not v.get('realtime') or not v.get('service')) else 'Atenção' if problems else 'OK'
        out.append(_r('defender', 'Antivírus / Microsoft Defender', status,
                      '; '.join(problems) or f'Tempo real ativo, assinaturas com {age} dia(s).', subs))

    v = raw.get('firewall')
    subs = ['PR.IR-01', 'DE.CM-01']
    if _err(v) or not v:
        out.append(_unavailable('firewall', 'Firewall do Windows', v, subs))
    else:
        off = [p['name'] for p in _as_list(v) if not p.get('enabled')]
        out.append(_r('firewall', 'Firewall do Windows', 'Falha' if off else 'OK',
                      f'Perfis desligados: {", ".join(off)}' if off else 'Todos os perfis ativos.', subs))

    v = raw.get('uac')
    subs = ['PR.AA-05', 'PR.PS-01']
    if _err(v) or not v:
        out.append(_unavailable('uac', 'Controle de Conta de Usuário (UAC)', v, subs))
    else:
        ok = v.get('lua') == 1 and v.get('admin_prompt') not in (0,)
        out.append(_r('uac', 'Controle de Conta de Usuário (UAC)', 'OK' if ok else 'Falha',
                      'UAC ativo.' if ok else 'UAC desativado ou elevação sem confirmação.', subs))

    v = raw.get('rdp')
    subs = ['PR.AA-03', 'PR.IR-01']
    if _err(v) or not v:
        out.append(_unavailable('rdp', 'Área de Trabalho Remota', v, subs))
    elif v.get('deny') == 1:
        out.append(_r('rdp', 'Área de Trabalho Remota', 'OK', 'Conexões RDP desabilitadas.', subs))
    else:
        nla = v.get('nla') == 1
        out.append(_r('rdp', 'Área de Trabalho Remota', 'Atenção' if nla else 'Falha',
                      'RDP habilitado ' + ('com NLA.' if nla else 'SEM autenticação em nível de rede (NLA).'), subs))

    v = raw.get('smb1')
    subs = ['PR.PS-01', 'PR.PS-02']
    if _err(v) or not v:
        out.append(_unavailable('smb1', 'Protocolo SMBv1', v, subs))
    else:
        on = bool(v.get('enabled'))
        out.append(_r('smb1', 'Protocolo SMBv1', 'Falha' if on else 'OK',
                      'SMBv1 HABILITADO (protocolo obsoleto, explorado pelo WannaCry).' if on
                      else 'SMBv1 desabilitado.', subs))

    v = raw.get('bitlocker')
    subs = ['PR.DS-01']
    if _err(v) or not v or v.get('protection') is None:
        out.append(_unavailable('bitlocker', 'Criptografia de disco (BitLocker)', v if _err(v) else
                                {'erro': 'requer Administrador'}, subs))
    else:
        on = v.get('protection') == 1
        out.append(_r('bitlocker', 'Criptografia de disco (BitLocker)', 'OK' if on else 'Falha',
                      f"Unidade {v.get('drive')}: " + ('protegida.' if on else 'SEM criptografia ativa.'), subs))

    v = raw.get('secureboot')
    subs = ['PR.PS-03', 'PR.PS-01']
    if _err(v) or not v:
        out.append(_unavailable('secureboot', 'Inicialização segura (Secure Boot)', v, subs))
    else:
        on = bool(v.get('enabled'))
        out.append(_r('secureboot', 'Inicialização segura (Secure Boot)', 'OK' if on else 'Atenção',
                      'Ativa.' if on else 'Desativada.', subs))

    v = raw.get('hotfix')
    subs = ['PR.PS-02', 'ID.RA-01']
    if _err(v) or not v or not v.get('last'):
        out.append(_unavailable('updates', 'Atualizações do Windows', v, subs))
    else:
        days = (today - date.fromisoformat(v['last'])).days
        status = 'OK' if days <= 45 else 'Atenção' if days <= 90 else 'Falha'
        out.append(_r('updates', 'Atualizações do Windows', status,
                      f"Última atualização instalada há {days} dia(s) ({v['last']}, {v.get('id', '')}).", subs))

    v = raw.get('admins')
    subs = ['PR.AA-05', 'PR.AA-01']
    if _err(v):
        out.append(_unavailable('admins', 'Administradores locais', v, subs))
    else:
        names = _as_list(v)
        status = 'OK' if len(names) <= 2 else 'Atenção'
        out.append(_r('admins', 'Administradores locais', status,
                      f'{len(names)} membro(s): {", ".join(names[:8])}', subs))

    g, nopwd = raw.get('guest'), raw.get('nopwd')
    subs = ['PR.AA-01', 'PR.AA-03']
    if _err(g) and _err(nopwd):
        out.append(_unavailable('accounts', 'Contas locais', g, subs))
    else:
        problems = []
        if isinstance(g, dict) and g.get('enabled'):
            problems.append('conta Convidado ATIVA')
        empty = [] if _err(nopwd) else _as_list(nopwd)
        if empty:
            problems.append(f'contas sem senha obrigatória: {", ".join(empty)}')
        out.append(_r('accounts', 'Contas locais', 'Falha' if problems else 'OK',
                      '; '.join(problems) or 'Convidado desativado; todas as contas exigem senha.', subs))

    pol = None if _err(raw.get('netaccounts')) else _net_accounts(raw.get('netaccounts'))
    subs = ['PR.AA-01', 'GV.PO-01']
    if not pol:
        out.append(_unavailable('pwpolicy', 'Política de senha e bloqueio', raw.get('netaccounts'), subs))
    else:
        problems = []
        if (pol['min_length'] or 0) < 8:
            problems.append(f"comprimento mínimo {pol['min_length'] or 0}")
        if not pol['lockout']:
            problems.append('sem bloqueio após tentativas inválidas')
        out.append(_r('pwpolicy', 'Política de senha e bloqueio', 'Atenção' if problems else 'OK',
                      '; '.join(problems) or f"Mínimo {pol['min_length']} caracteres; bloqueio após "
                      f"{pol['lockout']} tentativas.", subs))

    u, s = raw.get('uac'), raw.get('screensaver')
    subs = ['PR.AA-03', 'PR.PS-01']
    policy = u.get('inactivity') if isinstance(u, dict) and not _err(u) else None
    if policy:
        ok = int(policy) <= 900
        out.append(_r('screenlock', 'Bloqueio de tela por inatividade', 'OK' if ok else 'Atenção',
                      f'Política de inatividade: {int(policy) // 60} min.', subs))
    elif isinstance(s, dict) and not _err(s):
        secure = str(s.get('active')) == '1' and str(s.get('secure')) == '1'
        timeout = int(s.get('timeout') or 0)
        ok = secure and 0 < timeout <= 900
        out.append(_r('screenlock', 'Bloqueio de tela por inatividade', 'OK' if ok else 'Atenção',
                      f'Proteção de tela com senha após {timeout // 60} min.' if secure
                      else 'Sem bloqueio automático de tela configurado.', subs))
    else:
        out.append(_unavailable('screenlock', 'Bloqueio de tela por inatividade', s, subs))

    p, e = raw.get('pslog'), raw.get('eventlog')
    subs = ['PR.PS-04', 'DE.CM-03']
    problems = []
    if isinstance(e, dict) and not _err(e) and e.get('status') != 'Running':
        problems.append('serviço de Log de Eventos PARADO')
    if isinstance(p, dict) and not _err(p) and p.get('enabled') != 1:
        problems.append('registro de blocos de script do PowerShell desligado')
    status = 'Falha' if any('PARADO' in x for x in problems) else 'Atenção' if problems else 'OK'
    out.append(_r('logging', 'Registro de eventos e logs', status,
                  '; '.join(problems) or 'Log de eventos ativo e PowerShell registrando scripts.', subs))

    v = raw.get('smartscreen')
    subs = ['PR.PS-05']
    if _err(v) or not v:
        out.append(_unavailable('smartscreen', 'SmartScreen', v, subs))
    else:
        off = v.get('policy') == 0 or str(v.get('explorer') or '').lower() == 'off'
        out.append(_r('smartscreen', 'SmartScreen', 'Atenção' if off else 'OK',
                      'SmartScreen desligado.' if off else 'SmartScreen ativo ou no padrão do Windows.', subs))

    v = raw.get('restorepoints')
    subs = ['PR.DS-11', 'RC.RP-03']
    if _err(v) or not v:
        out.append(_r('backup', 'Pontos de restauração / backup', 'Indisponível',
                      'Não foi possível consultar (requer Administrador). Confirme o backup manualmente.', subs))
    else:
        n = int(v.get('count') or 0)
        out.append(_r('backup', 'Pontos de restauração / backup', 'OK' if n else 'Atenção',
                      f'{n} ponto(s) de restauração. Backups externos devem ser conferidos manualmente.', subs))

    v = raw.get('listening')
    subs = ['PR.IR-01', 'ID.AM-03', 'DE.CM-01']
    if _err(v):
        out.append(_unavailable('ports', 'Portas abertas na rede', v, subs))
    else:
        ports = [int(x) for x in _as_list(v) if str(x).isdigit()]
        risky = [f'{p} ({RISKY_PORTS[p]})' for p in ports if p in RISKY_PORTS]
        out.append(_r('ports', 'Portas abertas na rede', 'Atenção' if risky else 'OK',
                      (f'Serviços sensíveis expostos: {", ".join(risky)}. ' if risky else '')
                      + f'{len(ports)} porta(s) em escuta fora do localhost.', subs))

    v = raw.get('certificado')
    subs = ['PR.AA-01', 'PR.AA-03']
    if v is not None:
        if _err(v):
            out.append(_unavailable('appcert', 'Certificado do S-Cyber PM', v, subs))
        else:
            left = (date.fromisoformat(v['notafter']) - today).days
            status = 'Falha' if left < 0 or not v.get('privatekey') else 'Atenção' if left <= 60 else 'OK'
            out.append(_r('appcert', 'Certificado do S-Cyber PM', status,
                          f"Válido até {v['notafter']} ({left} dia(s)); chave privada "
                          f"{'presente' if v.get('privatekey') else 'AUSENTE'}.", subs))
    return out


def meta(raw):
    m = raw.get('meta') if isinstance(raw.get('meta'), dict) else {}
    return {'host': m.get('host', ''), 'user': m.get('user', ''), 'admin': bool(m.get('admin'))}
