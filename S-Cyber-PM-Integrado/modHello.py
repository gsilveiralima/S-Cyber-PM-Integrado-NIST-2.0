# ==============================================================================
#  S-Cyber PM - Cryptography and Digital Certificate Framework
# ------------------------------------------------------------------------------
#  Arquivo     : modHello.py
#  Descrição   : Acesso ao aplicativo pelo Windows Hello (PIN / biometria),
#                via UserConsentVerifier do Windows
#  Tipo        : Módulo de apoio
#  Versão      : 1.4 (versão do aplicativo)
#  Revisão     : 2026-11-15
#  Autores     : MAJ Daniel Medrado - PMGO
#                MAJ Leonidio Alves de Moraes Junior - PMGO
#                SGT Gabriel Silvieira Lima - PMGO
#  Instituição : Polícia Militar do Estado de Goiás
#  Contato     : leonidio.moraes@goias.gov.br
#  Licença     : Uso interno da instituição. Proibida a redistribuição sem
#                autorização.
#  Requisitos  : Python 3.11+ (64 bits), Windows 10/11 com Windows Hello
#  Codificação : UTF-8
# ==============================================================================
#  Histórico de revisões
#    Versão  Data        Alteração
#    1.4     2026-11-15  Criação
#                        UserConsentVerifier (sem IBuffer, que falha no PS 5)
# ==============================================================================
"""
S-Cyber PM - acesso ao aplicativo pelo Windows Hello (PIN ou biometria).

Usa o UserConsentVerifier do Windows: ele mostra a janela do Windows Hello e
só devolve "Verified" quando o usuário é reconhecido pelo PIN, pela impressão
digital ou pelo rosto cadastrados NO WINDOWS. O aplicativo apenas confia nessa
confirmação do sistema; não guarda digital, rosto nem PIN.

Por que isto, e não uma chave do KeyCredentialManager: o PowerShell 5 do
Windows não projeta o tipo IBuffer do WinRT (o objeto volta como
System.__ComObject e não pode ser convertido), então a leitura da chave
pública e da assinatura falha. O UserConsentVerifier devolve só um valor de
enumeração (sem buffers) e funciona de forma confiável.

SEGURANÇA: o "Hello ativado" fica no arquivo de opções, que já é cifrado e
autenticado com a chave do certificado (validado na abertura). Ninguém
consegue ligar o Hello editando o arquivo, e o "Verified" só vem do Windows
depois de um reconhecimento real. O Hello é um atalho opcional; a senha de
acesso continua valendo.

    disponivel()              -> (bool, motivo)
    verificar(mensagem)       -> True se o usuário passou no Hello; senão ErroHello
"""

import os
import subprocess

TIMEOUT = 120                            # segundos (o usuário pode demorar no Hello)


class ErroHello(Exception):
    """Falha no Windows Hello; a mensagem já está pronta para a tela."""


# O IAsyncOperation do WinRT vira Task via AsTask (como no PS_CAMERA do formCoruja).
_PS_INICIO = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$opT = [System.WindowsRuntimeSystemExtensions].GetMethods() |
    Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and
                   $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' } |
    Select-Object -First 1
function Aguardar($op, [Type]$t) { $task = $opT.MakeGenericMethod($t).Invoke($null, @($op)); $task.Wait(-1) | Out-Null; $task.Result }
[void][Windows.Security.Credentials.UI.UserConsentVerifier, Windows.Security.Credentials.UI, ContentType = WindowsRuntime]
"""

_PS_DISPONIVEL = _PS_INICIO + r"""
$av = Aguardar ([Windows.Security.Credentials.UI.UserConsentVerifier]::CheckAvailabilityAsync()) ([Windows.Security.Credentials.UI.UserConsentVerifierAvailability])
'OK ' + $av
"""

_PS_VERIFICAR = _PS_INICIO + r"""
$res = Aguardar ([Windows.Security.Credentials.UI.UserConsentVerifier]::RequestVerificationAsync($env:SCYBER_MOTIVO)) ([Windows.Security.Credentials.UI.UserConsentVerificationResult])
'OK ' + $res
"""

# Por que o Hello não está disponível (CheckAvailabilityAsync)
INDISPONIVEL = {
    "DeviceNotPresent": "não há leitor biométrico nem PIN do Windows Hello neste computador",
    "NotConfiguredForUser": "o Windows Hello não está configurado para este usuário "
                            "(Configurações > Contas > Opções de entrada)",
    "DisabledByPolicy": "o Windows Hello está desativado por política da organização",
    "DeviceBusy": "o dispositivo do Windows Hello está ocupado",
}
# Por que a verificação não passou (RequestVerificationAsync)
FALHA = {
    "DeviceNotPresent": "nenhum método do Windows Hello disponível.",
    "NotConfiguredForUser": "o Windows Hello não está configurado para este usuário.",
    "DisabledByPolicy": "o Windows Hello está desativado por política.",
    "DeviceBusy": "o dispositivo do Windows Hello está ocupado.",
    "RetriesExhausted": "número de tentativas do Windows Hello esgotado.",
    "Canceled": "o Windows Hello foi cancelado.",
}


def _powershell(script, **variaveis):
    """Roda o script e devolve o estado (texto após 'OK '). Mostra o Hello se preciso."""
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-Command", script],
            capture_output=True, encoding="utf-8", errors="replace", timeout=TIMEOUT,
            env=dict(os.environ, **variaveis),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except FileNotFoundError:
        raise ErroHello("PowerShell não encontrado.")
    except subprocess.TimeoutExpired:
        raise ErroHello("Tempo esgotado aguardando o Windows Hello.")
    linhas = [l.strip() for l in (r.stdout or "").splitlines() if l.strip()]
    resposta = linhas[-1] if linhas else (r.stderr or "").strip()
    if resposta.startswith("OK "):
        return resposta[3:].strip()
    raise ErroHello((resposta or "falha no Windows Hello").splitlines()[0])


def disponivel():
    """(True, '') se o Windows Hello pode ser usado; (False, motivo) caso contrário."""
    try:
        estado = _powershell(_PS_DISPONIVEL)
    except ErroHello as e:
        return (False, str(e))
    if estado == "Available":
        return (True, "")
    return (False, INDISPONIVEL.get(estado, f"Windows Hello indisponível ({estado})"))


def verificar(mensagem="Confirme sua identidade para o S-Cyber PM"):
    """Mostra o Windows Hello e devolve True se o usuário foi reconhecido
    (PIN/biometria). Levanta ErroHello se cancelar ou não passar."""
    estado = _powershell(_PS_VERIFICAR, SCYBER_MOTIVO=mensagem)
    if estado == "Verified":
        return True
    raise ErroHello(FALHA.get(estado, f"Windows Hello não confirmado ({estado})."))
