"""Diagnóstico Inteligente S-Cyber: um clique, do ativo à recomendação (S-Cyber 2.0, Fase 4).

Fluxo (o mesmo para todas as verificações):

  Ativo -> Coleta -> Evidência -> Achado -> Risco/Prioridade -> NIST -> Recomendação
        -> Correção (feita pelo usuário, com autorização) -> Nova verificação -> Comparação -> Auditoria

Reaproveita o que já existia, sem criar um segundo mecanismo:
* collector.run/evaluate: verificações SOMENTE DE LEITURA do Windows, ligadas ao CSF 2.0;
* core.save_collection: grava a coleta com o SHA-256 dos dados brutos (evidência);
* achados.from_collection: um achado por (ativo, verificação), com deduplicação e
  divergência quando a nova verificação contradiz a decisão registrada.

O que este módulo acrescenta:
* RECOMENDACOES: por que é risco, como corrigir, permissão, como verificar e referência;
* prioridade(): regra documentada (gravidade + criticidade do ativo + exposição);
* estado_exibicao(): os estados do S-Cyber 2.0 a partir dos estados internos;
* comparar(): evolução entre o diagnóstico anterior e o atual;
* executar(): o "um clique", com progresso e cancelamento entre as etapas.

Nada aqui altera o computador: as correções são orientadas, nunca executadas.
Uma verificação indisponível NUNCA conta como aprovada.
"""
from __future__ import annotations

from . import achados as ach
from . import collector, core

# ------------------------------------------------------------------ estados (vocabulário do S-Cyber 2.0)
# Situação da verificação (o que a coleta observou) e estado do achado (a decisão humana).
OBSERVADO_OK = 'Resultado observado: sem falha detectada'
INDISPONIVEL = 'Verificação indisponível'
ESTADOS_ACHADO = {
    'Novo': 'Suspeita (avaliação pendente)',
    'Descartado': 'Falso positivo (descartado com justificativa)',
    'Confirmado': 'Achado confirmado',
    'Correção registrada': 'Correção registrada (aguarda nova verificação e revisão)',
    'Encerrado': 'Risco tratado',
}


def estado_exibicao(situacao, estado_achado=None):
    """Texto do estado para a tela: a decisão humana (achado) prevalece sobre a coleta."""
    if estado_achado:
        return ESTADOS_ACHADO.get(estado_achado, estado_achado)
    if situacao == 'Indisponível':
        return INDISPONIVEL
    if situacao == 'OK':
        return OBSERVADO_OK
    return 'Suspeita (avaliação pendente)'


# ------------------------------------------------------------------ prioridade (metodologia)
GRAVIDADE = {'Falha': 3, 'Atenção': 2}
PESO_CRITICIDADE = {'Baixa': 0, 'Média': 1, 'Alta': 2, 'Crítica': 3}
# Verificações cuja falha deixa o computador alcançável pela rede (exposição)
EXPOSTOS = frozenset({'firewall', 'rdp', 'smb1', 'ports', 'az_storage_public', 'az_nsg'})
METODOLOGIA_PRIORIDADE = (
    'Pontuação = gravidade observada (Falha 3, Atenção 2) + criticidade do ativo (Baixa 0, Média 1, '
    'Alta 2, Crítica 3) + exposição à rede (1 para firewall, RDP, SMBv1, portas e, na nuvem, armazenamento '
    'público e regras de rede abertas). '
    'Prioridade: 6 ou mais = Crítica; 5 = Alta; 3 ou 4 = Média; até 2 = Baixa. '
    'É uma sugestão para ordenar o trabalho: quem confirma o achado define a prioridade final, '
    'com justificativa. Não é uma nota de segurança do computador.')


def prioridade(situacao, criticidade='Média', check_id=''):
    """(prioridade sugerida ou None, explicação). None quando não há o que corrigir."""
    if situacao not in GRAVIDADE:
        return None, ('verificação indisponível: precisa ser feita de outro jeito'
                      if situacao == 'Indisponível' else 'sem falha detectada')
    exposicao = 1 if check_id in EXPOSTOS else 0
    pontos = GRAVIDADE[situacao] + PESO_CRITICIDADE.get(criticidade, 1) + exposicao
    nivel = 'Crítica' if pontos >= 6 else 'Alta' if pontos == 5 else 'Média' if pontos >= 3 else 'Baixa'
    return nivel, (f'{situacao} ({GRAVIDADE[situacao]}) + ativo de criticidade {criticidade} '
                   f'({PESO_CRITICIDADE.get(criticidade, 1)})' + (' + exposto à rede (1)' if exposicao else '')
                   + f' = {pontos}')


# ------------------------------------------------------------------ recomendações (regras verificáveis)
def _rec(risco, corrigir, permissao, verificar, referencia):
    return {'risco': risco, 'corrigir': corrigir, 'permissao': permissao, 'verificar': verificar,
            'referencia': referencia}


_ADMIN = 'Administrador do computador'
RECOMENDACOES = {
    'defender': _rec(
        'Sem proteção em tempo real, ou com assinaturas antigas, programas maliciosos conhecidos não são '
        'bloqueados quando são baixados ou abertos.',
        'Segurança do Windows > Proteção contra vírus e ameaças > Gerenciar configurações: ligue a '
        '"Proteção em tempo real" e a "Proteção contra adulterações". Em "Atualizações de proteção", clique em '
        '"Verificar se há atualizações". Se usar outro antivírus, confirme que ele está ativo e atualizado.',
        _ADMIN, 'Novo diagnóstico: "Antivírus / Microsoft Defender" em OK (tempo real ativo, assinaturas com '
        'até 7 dias).', 'Microsoft Learn: Microsoft Defender Antivírus no app Segurança do Windows'),
    'firewall': _rec(
        'Com um perfil do firewall desligado, os serviços do computador ficam alcançáveis por outros '
        'computadores da mesma rede (inclusive redes públicas).',
        'Segurança do Windows > Firewall e proteção de rede: ative "Rede de domínio", "Rede privada" e '
        '"Rede pública". Alternativa (PowerShell como administrador): '
        'Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True',
        _ADMIN, 'Novo diagnóstico: "Firewall do Windows" em OK (todos os perfis ativos).',
        'Microsoft Learn: Firewall do Windows'),
    'uac': _rec(
        'Sem o UAC, tudo o que o usuário administrador executa ganha privilégio total sem confirmação, '
        'o que facilita a instalação de programas maliciosos.',
        'Painel de Controle > Contas de Usuário > Alterar configurações de Controle de Conta de Usuário: '
        'use pelo menos o nível padrão ("Notificar-me somente quando aplicativos tentarem fazer alterações '
        'no meu computador"). Reinicie o computador se o UAC estava desligado.',
        _ADMIN + ' (exige reinicialização)', 'Novo diagnóstico: "Controle de Conta de Usuário (UAC)" em OK.',
        'Microsoft Learn: Controle de Conta de Usuário'),
    'rdp': _rec(
        'A Área de Trabalho Remota ligada é um alvo frequente de força bruta. Sem autenticação em nível de rede '
        '(NLA), falhas podem ser exploradas antes do login (ex.: BlueKeep, CVE-2019-0708).',
        'Se ninguém acessa este computador remotamente: Configurações > Sistema > Área de Trabalho Remota > '
        'Desativado. Se o acesso é necessário: mantenha "Exigir que os dispositivos usem a Autenticação no '
        'Nível da Rede", restrinja quem pode conectar e nunca exponha a porta 3389 à internet.',
        _ADMIN, 'Novo diagnóstico: "Área de Trabalho Remota" em OK (desabilitada) ou Atenção com NLA, '
        'quando o uso for justificado.', 'Microsoft Learn: Área de Trabalho Remota e Autenticação no Nível '
        'da Rede; CISA KEV: CVE-2019-0708'),
    'smb1': _rec(
        'O SMBv1 é um protocolo obsoleto, sem as proteções das versões atuais, e foi explorado pelo '
        'WannaCry (EternalBlue, MS17-010).',
        'PowerShell como administrador: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol '
        'e reinicie. Alternativa: Ativar ou desativar recursos do Windows > desmarque "Suporte para '
        'Compartilhamento de Arquivos SMB 1.0/CIFS". Antes, confirme que nenhum equipamento antigo da rede '
        '(impressora, NAS) depende dele.',
        _ADMIN + ' (exige reinicialização)', 'Novo diagnóstico (como administrador): "Protocolo SMBv1" em OK.',
        'Microsoft Learn: Como detectar, habilitar e desabilitar SMBv1, SMBv2 e SMBv3 no Windows; '
        'boletim MS17-010'),
    'bitlocker': _rec(
        'Sem criptografia de disco, quem ficar com o computador ou com o disco (furto, perda, descarte) lê '
        'todos os arquivos, inclusive dados pessoais (LGPD).',
        'Painel de Controle > Criptografia de Unidade de Disco BitLocker > Ativar o BitLocker na unidade do '
        'sistema. GUARDE a chave de recuperação fora deste computador (conta da organização ou cofre). '
        'No Windows Home, use "Criptografia do dispositivo" (Configurações > Privacidade e segurança), '
        'quando disponível.',
        _ADMIN + ' (exige TPM; planeje a guarda da chave de recuperação)',
        'Novo diagnóstico como administrador: "Criptografia de disco (BitLocker)" em OK.',
        'Microsoft Learn: Visão geral do BitLocker'),
    'secureboot': _rec(
        'Sem a inicialização segura, um programa malicioso de inicialização (bootkit) pode carregar antes do '
        'Windows e do antivírus.',
        'Ative o Secure Boot na configuração UEFI do computador (firmware). Requer o modo UEFI, sem '
        'Legacy/CSM. Faça com o suporte técnico: mudar o firmware de um disco no formato antigo (MBR) pode '
        'impedir a inicialização.',
        'Suporte técnico, com acesso ao firmware do computador',
        'Novo diagnóstico como administrador: "Inicialização segura (Secure Boot)" em OK.',
        'Microsoft Learn: Inicialização segura (Secure Boot)'),
    'updates': _rec(
        'Falhas já corrigidas pelo fabricante continuam exploráveis enquanto a atualização não é instalada. '
        'Muitas estão no catálogo CISA KEV, de vulnerabilidades exploradas.',
        'Configurações > Windows Update > Verificar se há atualizações. Instale tudo, reinicie e mantenha a '
        'atualização automática ligada.',
        'Usuário (algumas atualizações pedem administrador)',
        'Novo diagnóstico: "Atualizações do Windows" em OK (última instalação há até 45 dias).',
        'Microsoft Learn: Windows Update; CISA: Known Exploited Vulnerabilities Catalog'),
    'admins': _rec(
        'Cada conta administradora a mais é uma conta cujo comprometimento dá controle total do computador.',
        'Deixe no grupo Administradores só as contas necessárias (S-Cyber PM > Usuários > Alterar '
        'permissões). Use uma conta comum no dia a dia e a administradora só quando precisar.',
        _ADMIN, 'Novo diagnóstico: "Administradores locais" em OK (até 2 membros).',
        'NIST CSF 2.0 PR.AA-05 (privilégio mínimo); CIS Controls v8, controle 5'),
    'accounts': _rec(
        'A conta Convidado ativa, ou uma conta sem senha, permite entrar no computador sem credencial.',
        'Desative a conta Convidado e defina senha nas contas sem senha, ou desative essas contas (S-Cyber PM > '
        'Usuários > Bloquear / Alterar senha).',
        _ADMIN, 'Novo diagnóstico: "Contas locais" em OK.', 'NIST CSF 2.0 PR.AA-01; CIS Controls v8, controle 5'),
    'pwpolicy': _rec(
        'Senhas curtas e sem bloqueio após tentativas erradas facilitam a adivinhação e a força bruta.',
        'Computador fora de domínio (Prompt como administrador): net accounts /minpwlen:12 e '
        'net accounts /lockoutthreshold:10 /lockoutduration:15 /lockoutwindow:15. '
        'Computador em domínio: ajuste a política de senha na GPO do domínio.',
        _ADMIN + ' (em domínio: administrador do domínio)',
        'Novo diagnóstico: "Política de senha e bloqueio" em OK.',
        'NIST SP 800-63B (diretrizes de autenticação); CIS Benchmarks: Account Policies'),
    'screenlock': _rec(
        'Com a tela aberta, qualquer pessoa que passe pelo computador usa a sessão do usuário.',
        'Configurações > Contas > Opções de entrada: em "Se você esteve ausente…", escolha "Quando o computador '
        'sair do modo de suspensão". Configurações > Sistema > Energia: tela e suspensão em até 15 minutos. '
        'Ao se levantar, use Windows + L.',
        'Usuário', 'Novo diagnóstico: "Bloqueio de tela por inatividade" em OK (até 15 minutos).',
        'NIST CSF 2.0 PR.AA-03; CIS Benchmarks: bloqueio de sessão por inatividade'),
    'logging': _rec(
        'Sem o log de eventos, ou sem o registro de scripts do PowerShell, um ataque não deixa rastro para a '
        'investigação.',
        'O serviço "Log de Eventos do Windows" deve estar em execução e com início Automático (services.msc). '
        'Registro de scripts (Windows Pro ou Enterprise): gpedit.msc > Configuração do Computador > Modelos '
        'Administrativos > Componentes do Windows > Windows PowerShell > "Ativar o Log de Blocos de Scripts '
        'do PowerShell".',
        _ADMIN, 'Novo diagnóstico: "Registro de eventos e logs" em OK.',
        'Microsoft Learn: about_Logging_Windows (PowerShell); NIST CSF 2.0 DE.CM-03'),
    'smartscreen': _rec(
        'Sem o SmartScreen, programas e downloads desconhecidos ou maliciosos não são alertados antes de abrir.',
        'Segurança do Windows > Controle de aplicativos e do navegador > Proteção baseada em reputação: ative '
        '"Verificar aplicativos e arquivos" e "SmartScreen para Microsoft Edge".',
        _ADMIN, 'Novo diagnóstico: "SmartScreen" em OK.', 'Microsoft Learn: Microsoft Defender SmartScreen'),
    'backup': _rec(
        'Sem cópia de segurança, ransomware ou defeito no disco causam perda definitiva. Pontos de '
        'restauração NÃO substituem o backup dos arquivos.',
        'Configure um backup periódico para mídia externa ou nuvem da organização (Backup do Windows ou '
        'Histórico de Arquivos) e TESTE a restauração. Para pontos de restauração: sysdm.cpl > Proteção do '
        'Sistema > Configurar > Ativar.',
        _ADMIN + ' (proteção do sistema)', 'Novo diagnóstico: "Pontos de restauração / backup" em OK, mais '
        'uma restauração de teste registrada como evidência.',
        'NIST CSF 2.0 PR.DS-11 e RC.RP-03; CIS Controls v8, controle 11'),
    'ports': _rec(
        'Serviços sensíveis em escuta na rede (SMB, RDP, WinRM, Telnet, FTP) são alvos frequentes de ataque '
        'e de movimentação lateral.',
        'Descubra qual programa usa a porta (Prompt como administrador: netstat -abno). Desative o serviço '
        'que não é usado, ou bloqueie a porta no Firewall do Windows pelo menos no perfil Público. Nunca '
        'exponha essas portas à internet.',
        _ADMIN, 'Novo diagnóstico: "Portas abertas na rede" sem serviços sensíveis, ou exceção justificada.',
        'NIST CSF 2.0 PR.IR-01; CIS Controls v8, controle 4'),
    'appcert': _rec(
        'Com o certificado vencido ou sem a chave privada, o S-Cyber PM não autentica o usuário nem assina '
        'documentos e relatórios.',
        'Peça ao administrador do S-Cyber PM a renovação ou um novo credenciamento (tela de abertura > '
        '"Criar certificado" e "pedido de credenciamento"). Não exporte nem copie a chave privada.',
        'Usuário e administrador do S-Cyber PM', 'Novo diagnóstico: "Certificado do S-Cyber PM" em OK.',
        'NIST CSF 2.0 PR.AA-01 e PR.AA-03'),
}
_AZ_LEITOR = 'Proprietário ou Colaborador da assinatura no Azure (o S-Cyber só lê, com o papel Leitor)'
RECOMENDACOES.update({
    'az_storage_public': _rec(
        'Blobs com acesso anônimo podem ser baixados por qualquer pessoa que descubra o endereço; contas de '
        'armazenamento abertas a todas as redes ficam expostas a força bruta e a vazamento de chaves.',
        'Portal do Azure > Conta de armazenamento > Configuração: "Permitir acesso anônimo a Blob" = Desabilitado. '
        'Em Rede: "Habilitado de redes virtuais e endereços IP selecionados" (ou ponto de extremidade privado). '
        'CLI: az storage account update -n <conta> -g <grupo> --allow-blob-public-access false --default-action Deny',
        _AZ_LEITOR, 'Nova verificação de nuvem: "Azure: exposição pública do armazenamento" em OK.',
        'Microsoft Learn: Impedir o acesso de leitura anônimo a contêineres e blobs; Configurar firewalls e redes '
        'virtuais do Armazenamento do Azure'),
    'az_storage_crypto': _rec(
        'Sem exigir HTTPS, ou aceitando TLS 1.0/1.1, os dados podem trafegar sem criptografia ou com protocolos '
        'com falhas conhecidas.',
        'Conta de armazenamento > Configuração: "Transferência segura necessária" = Habilitado e "Versão mínima do '
        'TLS" = 1.2. CLI: az storage account update -n <conta> -g <grupo> --https-only true --min-tls-version TLS1_2. '
        'A criptografia em repouso já é sempre ativa; chave do cliente (Key Vault) é opcional, conforme a política.',
        _AZ_LEITOR, 'Nova verificação de nuvem: "Azure: criptografia do armazenamento" em OK.',
        'Microsoft Learn: Exigir transferência segura; Impor uma versão mínima obrigatória do TLS'),
    'az_nsg': _rec(
        'SSH, RDP, SMB ou bancos de dados liberados para qualquer origem da internet são varridos e atacados em '
        'minutos por força bruta e por exploração de falhas conhecidas.',
        'Remova a regra de entrada ou restrinja a origem aos endereços da organização. Para administração remota, '
        'use Azure Bastion ou acesso Just-in-Time do Microsoft Defender para Nuvem, nunca a porta aberta.',
        _AZ_LEITOR, 'Nova verificação de nuvem: "Azure: regras de rede expostas à internet" em OK.',
        'Microsoft Learn: Grupos de segurança de rede; Azure Bastion; acesso just-in-time às VMs'),
    'az_owners': _rec(
        'Cada Proprietário (Owner) a mais é uma conta cujo comprometimento dá controle total da assinatura, '
        'inclusive para apagar backups.',
        'Mantenha no máximo 3 proprietários; use papéis menores (Colaborador, Leitor) e, se houver, o Privileged '
        'Identity Management (acesso de proprietário só quando necessário). Exija MFA de todos.',
        'Proprietário da assinatura', 'Nova verificação de nuvem: "Azure: proprietários da assinatura" em OK.',
        'Microsoft Learn: Práticas recomendadas do Azure RBAC; NIST CSF 2.0 PR.AA-05'),
    'az_backup': _rec(
        'Sem backup, uma exclusão acidental ou um ransomware na nuvem causa perda definitiva dos dados.',
        'Crie um Cofre dos Serviços de Recuperação e habilite o Azure Backup nas máquinas virtuais e nos dados '
        'críticos; TESTE uma restauração e registre a evidência.',
        _AZ_LEITOR, 'Nova verificação de nuvem: "Azure: backup" em OK, mais uma restauração de teste registrada.',
        'Microsoft Learn: O que é o serviço Backup do Azure?; NIST CSF 2.0 PR.DS-11'),
    'az_logging': _rec(
        'Sem exportar o Log de Atividades, quem fez o quê na assinatura só fica disponível por 90 dias: um incidente '
        'descoberto depois não pode ser investigado.',
        'Monitor > Log de atividades > Exportar Logs de Atividades > Adicionar configuração de diagnóstico, enviando '
        'para um workspace do Log Analytics ou uma conta de armazenamento com retenção definida pela política.',
        _AZ_LEITOR, 'Nova verificação de nuvem: "Azure: exportação do Log de Atividades" em OK.',
        'Microsoft Learn: Log de atividades do Azure Monitor (configurações de diagnóstico)'),
})
SEM_REGRA = _rec('Verificação sem regra de recomendação cadastrada.', 'Consulte o detalhe técnico e o suporte.',
                 'A definir', 'Novo diagnóstico.', '—')


def recomendacao(check_id):
    return RECOMENDACOES.get(check_id, SEM_REGRA)


# ------------------------------------------------------------------ ativo, itens e comparação
def garantir_ativo(db, host, tipo='Computador', nome=None):
    """Ativo deste host/assinatura (cria na 1ª vez, criticidade Média). Devolve o dict do ativo."""
    prefixos = ('Nuvem',) if tipo.startswith('Nuvem') else ('Computador', 'Servidor')
    for prefixo in prefixos:
        alvo = ach.asset_by_identifier(db, prefixo, host)
        if alvo:
            return alvo
    novo = ach.save_asset(db, nome or f'Este computador ({host})', tipo, host, '', 'Média',
                          notes='Cadastrado pelo Diagnóstico Inteligente. Ajuste a criticidade e o responsável.')
    return ach.asset(db, novo)


def itens(db, coleta_id, ativo=None):
    """Uma linha por verificação da coleta, com o estado, a prioridade e a recomendação."""
    ativo = ativo or {}
    criticidade = ativo.get('criticality', 'Média')
    por_ref = {}
    if ativo.get('id'):
        por_ref = {a['ref']: a for a in ach.achados(db, asset_id=ativo['id']) if a['source'] == 'Coleta técnica'}
    out = []
    for check, title, status, detail, subs in core.findings_for(db, coleta_id):
        a = por_ref.get(check)
        nivel, porque = prioridade(status, criticidade, check)
        out.append({'id': check, 'titulo': title, 'situacao': status, 'detalhe': detail,
                    'nist': [s for s in subs.split(',') if s], 'achado_id': a['id'] if a else None,
                    'estado': estado_exibicao(status, a['state'] if a else None),
                    'prioridade': (a['priority'] if a and a['priority'] else nivel), 'calculo': porque,
                    'recomendacao': recomendacao(check)})
    ordem = {'Crítica': 0, 'Alta': 1, 'Média': 2, 'Baixa': 3, None: 4}
    return sorted(out, key=lambda i: (ordem.get(i['prioridade'], 4), i['situacao'] == 'Indisponível', i['titulo']))


def coleta_anterior(db, coleta_id):
    """Coleta anterior do MESMO computador (para comparar), ou None."""
    host = db.execute('SELECT dec(host) FROM collections WHERE id=?', (int(coleta_id),)).fetchone()
    if not host:
        return None
    for cid, h in db.execute('SELECT id,dec(host) FROM collections WHERE id<? ORDER BY id DESC', (int(coleta_id),)):
        if (h or '').upper() == (host[0] or '').upper():
            return cid
    return None


_RANK = {'OK': 3, 'Atenção': 2, 'Falha': 1}       # Indisponível fica de fora: não é melhor nem pior


def comparar(db, anterior_id, atual_id):
    """[(check, título, antes, depois, tendência)] — tendência: Melhorou, Piorou, Igual, Nova,
    Não verificada agora, Sem comparação (indisponível em um dos dois)."""
    antes = {c: s for c, _, s, _, _ in core.findings_for(db, anterior_id)} if anterior_id else {}
    out = []
    for check, title, status, _, _ in core.findings_for(db, atual_id):
        if check not in antes:
            tendencia = 'Nova'
        elif status not in _RANK or antes[check] not in _RANK:
            tendencia = 'Igual' if status == antes[check] else 'Sem comparação'
        else:
            delta = _RANK[status] - _RANK[antes[check]]
            tendencia = 'Melhorou' if delta > 0 else 'Piorou' if delta < 0 else 'Igual'
        out.append((check, title, antes.get(check, '—'), status, tendencia))
    atuais = {c for c, *_ in out}
    for check, title, status, _, _ in (core.findings_for(db, anterior_id) if anterior_id else []):
        if check not in atuais:
            out.append((check, title, status, '—', 'Não verificada agora'))
    return out


def resumo(lista, comparacao=()):
    """Contagens para a tela. 'Indisponível' nunca entra como aprovado."""
    conta = {'OK': 0, 'Atenção': 0, 'Falha': 0, 'Indisponível': 0}
    for i in lista:
        conta[i['situacao']] = conta.get(i['situacao'], 0) + 1
    tend = {}
    for *_, t in comparacao:
        tend[t] = tend.get(t, 0) + 1
    verificadas = conta['OK'] + conta['Atenção'] + conta['Falha']
    return {'situacoes': conta, 'verificadas': verificadas, 'total': len(lista),
            'cobertura': f'{verificadas} de {len(lista)} verificações feitas',
            'prioritarias': sum(1 for i in lista if i['prioridade'] in ('Crítica', 'Alta')),
            'tendencias': tend}


# ------------------------------------------------------------------ o "um clique"
ESCOPO = ('Este computador, somente leitura: antivírus, firewall, UAC, Área de Trabalho Remota, SMBv1, '
          'BitLocker, Secure Boot, atualizações, administradores e contas locais, política de senha, bloqueio '
          'de tela, logs, SmartScreen, backup, portas em escuta e o certificado do S-Cyber PM. Nada é alterado '
          'e nada é enviado para a internet. Como administrador, mais itens podem ser verificados.')
ETAPAS = ('Preparando', 'Coletando no Windows (somente leitura)', 'Avaliando', 'Registrando a evidência',
          'Atualizando os achados', 'Montando as recomendações', 'Comparando com o diagnóstico anterior')


class Cancelado(Exception):
    pass


def executar(db, thumb=None, evidence_folder=None, progresso=None, cancelado=None, coletar=None):
    """Roda o diagnóstico completo numa só thread (testes, linha de comando). A interface usa
    coletar() numa thread e registrar() na thread da tela, porque o banco pertence a ela.
    progresso(n, etapa) informa a etapa; cancelado() é consultado até a gravação começar
    (a consulta ao Windows em andamento termina sozinha e é DESCARTADA)."""
    progresso = progresso or (lambda n, etapa: None)
    cancelado = cancelado or (lambda: False)
    coletar = coletar or collector.run

    def passo(n):
        if cancelado():
            raise Cancelado('Diagnóstico cancelado: nada foi gravado.')
        progresso(n, ETAPAS[n])

    passo(0)                     # nada é gravado antes da etapa 2: cancelar não deixa resto
    passo(1)
    raw = coletar(thumb)
    if cancelado():
        raise Cancelado('Diagnóstico cancelado: nada foi gravado.')
    return registrar(db, raw, evidence_folder, progresso)


def registrar(db, raw, evidence_folder=None, progresso=None, nuvem=False):
    """Da coleta bruta ao resultado: avalia, grava a evidência, atualiza os achados, monta as
    recomendações e compara com o diagnóstico anterior do mesmo computador (ou assinatura,
    com nuvem=True: dados de nist_intelligence.nuvem, mesmo fluxo)."""
    from . import nuvem as nv
    progresso = progresso or (lambda n, etapa: None)
    progresso(2, ETAPAS[2])
    resultados = nv.evaluate(raw) if nuvem else collector.evaluate(raw)
    meta = nv.meta(raw) if nuvem else collector.meta(raw)
    progresso(3, ETAPAS[3])
    if nuvem:
        origem = 'Nuvem (simulada)' if meta['simulado'] else 'Nuvem Azure'
        ativo = garantir_ativo(db, meta['host'], 'Nuvem (assinatura)',
                               f"Azure: {meta['nome'] or meta['host']}" + (' [SIMULADO]' if meta['simulado'] else ''))
    else:
        origem = 'Local'
        ativo = garantir_ativo(db, meta['host'] or 'este-computador')
    coleta_id = core.save_collection(db, meta, raw, resultados, source=origem)
    progresso(4, ETAPAS[4])
    ach.from_collection(db, coleta_id, evidence_folder)
    progresso(5, ETAPAS[5])
    ativo = ach.asset(db, ativo['id'])
    lista = itens(db, coleta_id, ativo)
    progresso(6, ETAPAS[6])
    anterior = coleta_anterior(db, coleta_id)
    comparacao = comparar(db, anterior, coleta_id) if anterior else []
    res = resumo(lista, comparacao)
    core.audit(db, 'Diagnóstico', 'Executar', coleta_id,
               f"{meta['host']}: {res['cobertura']}; Falha {res['situacoes']['Falha']}, "
               f"Atenção {res['situacoes']['Atenção']}, Indisponível {res['situacoes']['Indisponível']}"
               + (f'; comparado com a coleta #{anterior}' if anterior else ''))
    db.commit()
    return {'coleta_id': coleta_id, 'anterior_id': anterior, 'ativo': ativo, 'itens': lista,
            'comparacao': comparacao, 'resumo': res, 'admin': meta['admin'], 'nuvem': nuvem,
            'simulado': bool(meta.get('simulado'))}


def ultimo(db):
    """O último diagnóstico local já gravado (para mostrar ao abrir o painel), ou None."""
    row = db.execute("SELECT id,dec(host) FROM collections WHERE source='Local' ORDER BY id DESC LIMIT 1").fetchone()
    if not row:
        return None
    coleta_id, host = row
    ativo = ach.asset_by_identifier(db, 'Computador', host) or ach.asset_by_identifier(db, 'Servidor', host) or {}
    lista = itens(db, coleta_id, ativo)
    anterior = coleta_anterior(db, coleta_id)
    comparacao = comparar(db, anterior, coleta_id) if anterior else []
    admin = db.execute('SELECT admin FROM collections WHERE id=?', (coleta_id,)).fetchone()[0]
    return {'coleta_id': coleta_id, 'anterior_id': anterior, 'ativo': ativo, 'itens': lista,
            'comparacao': comparacao, 'resumo': resumo(lista, comparacao), 'admin': bool(admin)}
