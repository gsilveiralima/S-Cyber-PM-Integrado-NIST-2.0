"""Segurança em nuvem: Microsoft Azure, SOMENTE LEITURA (S-Cyber 2.0, Fase 5; UC6).

Verifica uma assinatura do Azure pela API oficial do Azure Resource Manager e devolve
o mesmo formato do coletor do Windows (id, título, situação, detalhe, subcategorias
NIST), para entrar no MESMO fluxo do Diagnóstico Inteligente: ativo -> coleta ->
evidência -> achado -> prioridade -> NIST -> recomendação -> nova verificação.

Conjunto mínimo de verificações (§18 do S-Cyber 2.0):
  az_storage_public   exposição pública do armazenamento (blobs anônimos, rede aberta)
  az_storage_crypto   criptografia: só HTTPS, TLS mínimo 1.2 e chave da criptografia em repouso
  az_nsg              regras de rede que abrem SSH/RDP/SMB/bancos de dados para a internet
  az_owners           permissões: quantos "Proprietário" (Owner) na assinatura
  az_backup           backup: cofres do Azure Backup frente às máquinas virtuais
  az_logging          registro: o Log de Atividades é exportado (configuração de diagnóstico)

Acesso: usa o Azure CLI já conectado pelo próprio usuário ("az login"). O S-Cyber só
pede um token de acesso ao CLI (fica só na memória, nunca é gravado) e faz GETs. A
conta precisa apenas do papel "Leitor" (Reader) na assinatura. Nada é criado, alterado
ou apagado. Sem o CLI ou sem permissão, a verificação fica INDISPONÍVEL, nunca aprovada.

Demonstração: AMBIENTE_SIMULADO traz dados sintéticos de uma empresa fictícia, no
formato da API, claramente identificados como simulados em todo lugar onde aparecem.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import urllib.parse

from . import fontes

ARM = 'https://management.azure.com'
# Versões da API do Azure Resource Manager (conferir na 1ª execução real; erro vira Indisponível)
API = {
    'storage': ('Microsoft.Storage/storageAccounts', '2023-01-01'),
    'nsg': ('Microsoft.Network/networkSecurityGroups', '2023-09-01'),
    'roles': ('Microsoft.Authorization/roleAssignments', '2022-04-01'),
    'vaults': ('Microsoft.RecoveryServices/vaults', '2023-04-01'),
    'vms': ('Microsoft.Compute/virtualMachines', '2023-03-01'),
    'diag': ('Microsoft.Insights/diagnosticSettings', '2021-05-01-preview'),
}
OWNER = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'          # papel interno "Owner" do Azure
PORTAS_SENSIVEIS = {'22': 'SSH', '3389': 'RDP', '445': 'SMB', '1433': 'SQL Server', '3306': 'MySQL',
                    '5432': 'PostgreSQL', '5985': 'WinRM', '5986': 'WinRM', '23': 'Telnet', '21': 'FTP'}
ORIGENS_ABERTAS = {'*', 'internet', '0.0.0.0/0', 'any', '::/0'}
TIMEOUT_CLI = 60


class ErroNuvem(RuntimeError):
    pass


# ------------------------------------------------------------------ acesso (Azure CLI)
def _az(*args):
    exe = shutil.which('az') or shutil.which('az.cmd')
    if not exe:
        raise ErroNuvem('Azure CLI não encontrado. Instale o Azure CLI e entre com "az login" (conta com papel '
                        'Leitor/Reader na assinatura), ou use a demonstração simulada.')
    try:
        r = subprocess.run([exe, *args, '--output', 'json'], capture_output=True, text=True, encoding='utf-8',
                           errors='replace', timeout=TIMEOUT_CLI,
                           creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    except subprocess.TimeoutExpired as exc:
        raise ErroNuvem('O Azure CLI não respondeu a tempo.') from exc
    if r.returncode:
        msg = (r.stderr or r.stdout).strip().splitlines()
        raise ErroNuvem('Azure CLI: ' + (msg[-1] if msg else 'falhou') +
                        ' Entre com "az login" e confira a assinatura ("az account show").')
    return json.loads(r.stdout)


def conta_azure():
    """{'id','name','tenantId','user'} da assinatura ativa no Azure CLI."""
    c = _az('account', 'show')
    return {'id': c.get('id', ''), 'name': c.get('name', ''), 'tenantId': c.get('tenantId', ''),
            'user': (c.get('user') or {}).get('name', '')}


def _token():
    return _az('account', 'get-access-token', '--resource', ARM + '/')['accessToken']


def _listar(get, url):
    """Todos os itens de uma lista do ARM (segue nextLink)."""
    itens, proxima, voltas = [], url, 0
    while proxima and voltas < 50:
        dados = get(proxima)
        itens += dados.get('value', [])
        proxima, voltas = dados.get('nextLink'), voltas + 1
    return itens


def coletar_azure(conta=None, token=None, http=None):
    """Dados brutos de uma assinatura (só GET). Cada parte que falhar vira {'erro': motivo}."""
    conta = conta or conta_azure()
    token = token or _token()
    http = http or fontes.http_get
    sub = conta['id']

    def get(url):
        status, corpo = http(url, {'Authorization': f'Bearer {token}', 'Accept': 'application/json'}, timeout=30)
        return json.loads(corpo or b'{}') if status != 404 else {}

    raw = {'meta': {'host': sub, 'user': conta.get('user', ''), 'admin': False, 'nuvem': 'Azure',
                    'nome': conta.get('name', ''), 'simulado': False}}
    for chave, (tipo, versao) in API.items():
        url = f'{ARM}/subscriptions/{urllib.parse.quote(sub)}/providers/{tipo}?api-version={versao}'
        try:
            raw[chave] = _listar(get, url)
        except fontes.FalhaFonte as exc:
            raw[chave] = {'erro': str(exc)}
        except (ValueError, OSError) as exc:
            raw[chave] = {'erro': f'resposta inválida ({exc})'}
    return raw


# ------------------------------------------------------------------ avaliação
def _r(id_, title, status, detail, subs):
    return {'id': id_, 'title': title, 'status': status, 'detail': detail, 'subs': subs}


def _erro(v):
    return isinstance(v, dict) and 'erro' in v


def _indisp(id_, title, v, subs):
    motivo = v.get('erro', 'sem dados') if isinstance(v, dict) else 'sem dados'
    return _r(id_, title, 'Indisponível', f'Não foi possível consultar ({motivo[:160]}).', subs)


def _nome(recurso):
    return recurso.get('name') or recurso.get('id', '?').rsplit('/', 1)[-1]


def _portas(regra):
    p = regra.get('properties', {})
    faixas = [p.get('destinationPortRange')] + list(p.get('destinationPortRanges') or [])
    abertas = []
    for faixa in filter(None, faixas):
        if faixa == '*':
            return ['todas as portas']
        for porta, nome in sorted(PORTAS_SENSIVEIS.items(), key=lambda x: int(x[0])):
            if '-' in faixa:
                a, b = faixa.split('-', 1)
                if a.isdigit() and b.isdigit() and int(a) <= int(porta) <= int(b):
                    abertas.append(f'{porta} ({nome})')
            elif faixa == porta:
                abertas.append(f'{porta} ({nome})')
    return abertas


def _aberta_a_internet(regra):
    p = regra.get('properties', {})
    origens = [p.get('sourceAddressPrefix')] + list(p.get('sourceAddressPrefixes') or [])
    return (p.get('direction') == 'Inbound' and p.get('access') == 'Allow'
            and any(str(o).lower() in ORIGENS_ABERTAS for o in origens if o))


def evaluate(raw):
    """Verificações com OK / Atenção / Falha / Indisponível, como collector.evaluate."""
    out = []

    contas = raw.get('storage')
    subs = ['PR.DS-01', 'PR.AA-05', 'PR.IR-01']
    if _erro(contas) or contas is None:
        out.append(_indisp('az_storage_public', 'Azure: exposição pública do armazenamento', contas, subs))
    else:
        publicas, abertas, sem_info = [], [], []
        for c in contas:
            p = c.get('properties', {})
            if p.get('allowBlobPublicAccess') is True:
                publicas.append(_nome(c))
            elif p.get('allowBlobPublicAccess') is None:
                sem_info.append(_nome(c))
            if p.get('publicNetworkAccess', 'Enabled') != 'Disabled' and \
                    (p.get('networkAcls') or {}).get('defaultAction', 'Allow') == 'Allow':
                abertas.append(_nome(c))
        problemas = ([f'acesso anônimo a blobs PERMITIDO em: {", ".join(publicas)}'] if publicas else []) + \
                    ([f'aceitam conexões de qualquer rede: {", ".join(abertas)}'] if abertas else []) + \
                    ([f'acesso anônimo não informado pela API em: {", ".join(sem_info)}'] if sem_info else [])
        status = 'Falha' if publicas else 'Atenção' if (abertas or sem_info) else 'OK'
        if not contas:
            texto = 'Nenhuma conta de armazenamento na assinatura.'
        else:
            texto = '; '.join(problemas) or f'{len(contas)} conta(s) sem acesso anônimo e com rede restrita.'
        out.append(_r('az_storage_public', 'Azure: exposição pública do armazenamento', status, texto, subs))

    subs = ['PR.DS-01', 'PR.DS-02']
    if _erro(contas) or contas is None:
        out.append(_indisp('az_storage_crypto', 'Azure: criptografia do armazenamento', contas, subs))
    else:
        sem_https, tls_antigo, chaves = [], [], {}
        for c in contas:
            p = c.get('properties', {})
            if p.get('supportsHttpsTrafficOnly') is False:
                sem_https.append(_nome(c))
            if p.get('minimumTlsVersion') in ('TLS1_0', 'TLS1_1'):
                tls_antigo.append(f"{_nome(c)} ({p['minimumTlsVersion']})")
            fonte_chave = (p.get('encryption') or {}).get('keySource', 'Microsoft.Storage')
            chaves[fonte_chave] = chaves.get(fonte_chave, 0) + 1
        problemas = ([f'aceitam HTTP sem criptografia: {", ".join(sem_https)}'] if sem_https else []) + \
                    ([f'TLS mínimo abaixo de 1.2: {", ".join(tls_antigo)}'] if tls_antigo else [])
        repouso = ', '.join(f'{n} com chave {"do cliente (Key Vault)" if k == "Microsoft.Keyvault" else "da Microsoft"}'
                            for k, n in sorted(chaves.items()))
        out.append(_r('az_storage_crypto', 'Azure: criptografia do armazenamento',
                      'Falha' if sem_https else 'Atenção' if tls_antigo else 'OK',
                      ('; '.join(problemas) + '. ' if problemas else 'Só HTTPS e TLS 1.2 ou superior. ')
                      + (f'Criptografia em repouso: {repouso}.' if contas else 'Nenhuma conta de armazenamento.'),
                      subs))

    grupos = raw.get('nsg')
    subs = ['PR.IR-01', 'DE.CM-01']
    if _erro(grupos) or grupos is None:
        out.append(_indisp('az_nsg', 'Azure: regras de rede expostas à internet', grupos, subs))
    else:
        expostas = []
        for g in grupos:
            regras = (g.get('properties') or {}).get('securityRules') or []
            for regra in regras:
                portas = _portas(regra) if _aberta_a_internet(regra) else []
                if portas:
                    expostas.append(f"{_nome(g)}/{_nome(regra)}: {', '.join(portas)}")
        out.append(_r('az_nsg', 'Azure: regras de rede expostas à internet', 'Falha' if expostas else 'OK',
                      ('Liberado para qualquer origem da internet: ' + '; '.join(expostas[:6])) if expostas
                      else f'{len(grupos)} grupo(s) de segurança sem serviço sensível aberto à internet.', subs))

    papeis = raw.get('roles')
    subs = ['PR.AA-05', 'GV.RR-02']
    if _erro(papeis) or papeis is None:
        out.append(_indisp('az_owners', 'Azure: proprietários da assinatura', papeis, subs))
    else:
        donos = [p for p in papeis if (p.get('properties') or {}).get('roleDefinitionId', '').lower().endswith(OWNER)]
        status = 'OK' if len(donos) <= 3 else 'Atenção'
        out.append(_r('az_owners', 'Azure: proprietários da assinatura', status,
                      f'{len(donos)} atribuição(ões) do papel Proprietário (Owner) e {len(papeis)} atribuição(ões) '
                      'no total.' + (' Mais de 3 proprietários amplia o risco de uma conta comprometida controlar '
                                     'tudo.' if status != 'OK' else ''), subs))

    cofres, vms = raw.get('vaults'), raw.get('vms')
    subs = ['PR.DS-11', 'RC.RP-03']
    if _erro(cofres) or cofres is None:
        out.append(_indisp('az_backup', 'Azure: backup', cofres, subs))
    else:
        n_vms = None if _erro(vms) or vms is None else len(vms)
        if cofres:
            status, texto = 'OK', f'{len(cofres)} cofre(s) do Azure Backup.'
        elif n_vms:
            status, texto = 'Falha', f'{n_vms} máquina(s) virtual(is) e NENHUM cofre do Azure Backup.'
        else:
            status, texto = 'Atenção', 'Nenhum cofre do Azure Backup; confirme como os dados são copiados.'
        if n_vms is not None:
            texto += f' Máquinas virtuais: {n_vms}. Confira se cada uma está protegida e teste a restauração.'
        out.append(_r('az_backup', 'Azure: backup', status, texto, subs))

    diag = raw.get('diag')
    subs = ['PR.PS-04', 'DE.CM-03']
    if _erro(diag) or diag is None:
        out.append(_indisp('az_logging', 'Azure: exportação do Log de Atividades', diag, subs))
    else:
        out.append(_r('az_logging', 'Azure: exportação do Log de Atividades', 'OK' if diag else 'Atenção',
                      f'{len(diag)} configuração(ões) de diagnóstico exportando o Log de Atividades.' if diag else
                      'O Log de Atividades não é exportado (fica só 90 dias no Azure): investigar um incidente '
                      'antigo fica impossível.', subs))
    return out


def meta(raw):
    m = raw.get('meta') if isinstance(raw.get('meta'), dict) else {}
    return {'host': m.get('host', ''), 'user': m.get('user', ''), 'admin': False,
            'nome': m.get('nome', ''), 'simulado': bool(m.get('simulado'))}


# ------------------------------------------------------------------ demonstração (dados SINTÉTICOS)
def _sa(nome, publico, https=True, tls='TLS1_2', rede='Allow', chave='Microsoft.Storage'):
    return {'name': nome, 'id': f'/subscriptions/demo/resourceGroups/rg-demo/providers/Microsoft.Storage/'
                                 f'storageAccounts/{nome}',
            'properties': {'allowBlobPublicAccess': publico, 'supportsHttpsTrafficOnly': https,
                           'minimumTlsVersion': tls, 'publicNetworkAccess': 'Enabled',
                           'networkAcls': {'defaultAction': rede}, 'encryption': {'keySource': chave}}}


def _regra(nome, porta, origem='*'):
    return {'name': nome, 'properties': {'direction': 'Inbound', 'access': 'Allow', 'protocol': 'Tcp',
                                         'sourceAddressPrefix': origem, 'destinationPortRange': porta}}


def _papel(guid):
    return {'properties': {'roleDefinitionId': f'/subscriptions/demo/providers/Microsoft.Authorization/'
                                              f'roleDefinitions/{guid}', 'principalType': 'User'}}


AMBIENTE_SIMULADO = {
    'meta': {'host': 'demo-simulada-empresa-ficticia', 'user': 'demonstracao@empresa-ficticia.example',
             'admin': False, 'nuvem': 'Azure', 'nome': 'DEMONSTRAÇÃO SIMULADA — Empresa Fictícia Ltda',
             'simulado': True},
    'storage': [_sa('stdemodocumentos', True, rede='Allow'), _sa('stdemobackup', False, tls='TLS1_0',
                                                                  rede='Deny')],
    'nsg': [{'name': 'nsg-servidor-web', 'properties': {'securityRules': [
        _regra('permitir-https', '443'), _regra('acesso-remoto-admin', '3389', 'Internet')]}}],
    'roles': [_papel(OWNER), _papel(OWNER), _papel(OWNER), _papel(OWNER),
              _papel('acdd72a7-3385-48ef-bd42-f606fba81ae7')],
    'vaults': [],
    'vms': [{'name': 'vm-servidor-web'}],
    'diag': [],
}


def ambiente_simulado():
    """Cópia dos dados sintéticos (para não alterar o original)."""
    return json.loads(json.dumps(AMBIENTE_SIMULADO))

