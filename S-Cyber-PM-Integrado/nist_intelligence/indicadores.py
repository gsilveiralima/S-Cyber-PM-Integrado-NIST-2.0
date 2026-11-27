"""Indicadores de evolução da segurança (S-Cyber 2.0, Fase 6).

Só usa o que está registrado no banco: diagnósticos (coletas), achados, riscos, incidentes e a
avaliação do CSF 2.0. Não há nota nem porcentagem de "segurança": cada número é uma contagem
com origem conhecida, e a tela diferencia três situações que costumam ser confundidas:

* sem avaliação  — a verificação nunca foi feita (não se sabe nada);
* indisponível   — a verificação foi tentada, mas não pôde ser feita (não conta como aprovada);
* sem falha detectada — a verificação foi feita e não encontrou problema (não prova segurança).
"""
from __future__ import annotations

from datetime import date

from . import achados as ach
from . import core
from . import diagnostico as dg

METODOLOGIA = (
    'Como os indicadores são calculados: cada diagnóstico conta as verificações por situação '
    '(sem falha detectada, atenção, falha e indisponível). "Cobertura" é quantas verificações '
    'puderam ser feitas, do total tentado; as indisponíveis nunca contam como aprovadas. '
    '"Prioritárias" são as falhas e atenções com prioridade Crítica ou Alta pela regra documentada '
    '(gravidade + criticidade do ativo + exposição à rede). "Riscos críticos" são os riscos abertos '
    'ou em tratamento com probabilidade × impacto de 6 ou mais (escala 1 a 3). "Correções '
    'verificadas" são achados encerrados depois de nova verificação e revisão. A comparação é '
    'sempre entre dois diagnósticos do MESMO ativo. Nenhum número aqui é uma nota de segurança '
    'nem declara conformidade com o NIST CSF 2.0 ou com a LGPD.')

_PRIORITARIAS = ('Crítica', 'Alta')


def _ativo_da_coleta(db, host, origem):
    prefixos = (('Nuvem',) if origem.startswith('Nuvem') else ('Domínio',) if origem.startswith('Domínio')
                else ('Computador', 'Servidor'))
    for prefixo in prefixos:
        alvo = ach.asset_by_identifier(db, prefixo, host)
        if alvo:
            return alvo
    return {}


def evolucao(db, limite=12):
    """Diagnósticos em ordem de data (mais antigo primeiro), no máximo `limite`, com as contagens
    por situação, a cobertura e as prioritárias de cada um."""
    linhas = db.execute('SELECT id,run_at,dec(host),source FROM collections ORDER BY id DESC LIMIT ?',
                        (int(limite),)).fetchall()
    out = []
    for cid, quando, host, origem in reversed(linhas):
        itens = dg.itens(db, cid, _ativo_da_coleta(db, host or '', origem or 'Local'))
        res = dg.resumo(itens)
        s = res['situacoes']
        out.append({'coleta_id': cid, 'quando': quando, 'host': host or '?', 'origem': origem or 'Local',
                    'total': res['total'], 'verificadas': res['verificadas'], 'ok': s['OK'],
                    'atencao': s['Atenção'], 'falha': s['Falha'], 'indisponivel': s['Indisponível'],
                    'prioritarias': sum(1 for i in itens if i['situacao'] in ('Falha', 'Atenção')
                                        and i['prioridade'] in _PRIORITARIAS)})
    return out


def _comparacao_mais_recente(db):
    """Última comparação entre dois diagnósticos do mesmo ativo: (atual, anterior, tendências)."""
    for (cid,) in db.execute('SELECT id FROM collections ORDER BY id DESC').fetchall():
        anterior = dg.coleta_anterior(db, cid)
        if anterior:
            tend = {}
            for *_, t in dg.comparar(db, anterior, cid):
                tend[t] = tend.get(t, 0) + 1
            return {'atual': cid, 'anterior': anterior, 'tendencias': tend}
    return None


def indicadores(db, hoje=None):
    """Números do painel de evolução. Cada chave é uma contagem do que foi registrado."""
    hoje = hoje or date.today()
    por_estado = {}
    for a in ach.achados(db):
        por_estado[a['state']] = por_estado.get(a['state'], 0) + 1
    pendencias = ach.pending(db, hoje)
    resumo_nist = core.summary(db)
    ativos = ach.assets(db)
    hosts_avaliados = {(h or '').upper() for _, _, h, *_ in core.collections_by_host(db)}
    avaliados = sum(1 for a in ativos if (a['identifier'] or '').upper() in hosts_avaliados)
    riscos_tratados = db.execute("SELECT COUNT(*) FROM risks WHERE status='Tratado'").fetchone()[0]
    incidentes = db.execute('SELECT COUNT(*) FROM incidents').fetchone()[0]
    serie = evolucao(db, limite=1)
    ultimo = serie[-1] if serie else None
    return {
        'ativos_cadastrados': len(ativos),
        'ativos_avaliados': avaliados,
        'diagnosticos': db.execute('SELECT COUNT(*) FROM collections').fetchone()[0],
        'achados_suspeitos': por_estado.get('Novo', 0),
        'achados_confirmados': por_estado.get('Confirmado', 0),
        'correcoes_aguardando': por_estado.get('Correção registrada', 0),
        'correcoes_verificadas': por_estado.get('Encerrado', 0),
        'falsos_positivos': por_estado.get('Descartado', 0),
        'acoes_vencidas': sum(1 for tipo, _ in pendencias if tipo == 'Ação vencida'),
        'divergencias': sum(1 for tipo, _ in pendencias if tipo == 'Divergência'),
        'riscos_criticos': resumo_nist['high_risks'],
        'riscos_tratados': riscos_tratados,
        'incidentes': incidentes,
        'incidentes_abertos': resumo_nist['open_incidents'],
        'subcategorias_avaliadas': resumo_nist['evaluated'],
        'subcategorias_total': resumo_nist['total_subs'],
        'ultimo_diagnostico': ultimo,
        'comparacao': _comparacao_mais_recente(db),
    }


def leitura(ind):
    """Frases simples para o modo básico. Diferencia 'não avaliado', 'indisponível' e
    'sem falha detectada' e nunca transforma ausência de dado em resultado bom."""
    frases = []
    ultimo = ind['ultimo_diagnostico']
    if not ultimo:
        frases.append('Nenhum diagnóstico feito ainda: a segurança deste ambiente ainda não foi avaliada. '
                      'Clique em "Diagnóstico Inteligente" para começar.')
    else:
        frases.append(f"Último diagnóstico ({ultimo['quando'][:16].replace('T', ' ')}, {ultimo['host']}): "
                      f"{ultimo['verificadas']} de {ultimo['total']} verificações feitas; "
                      f"{ultimo['falha']} falha(s), {ultimo['atencao']} atenção(ões), "
                      f"{ultimo['ok']} sem falha detectada.")
        if ultimo['indisponivel']:
            frases.append(f"{ultimo['indisponivel']} verificação(ões) não puderam ser feitas: elas não contam "
                          'como aprovadas. Rode como administrador ou verifique de outro jeito.')
        if ultimo['prioritarias']:
            frases.append(f"{ultimo['prioritarias']} problema(s) com prioridade Crítica ou Alta: comece por eles.")
    comp = ind['comparacao']
    if comp:
        t = comp['tendencias']
        frases.append(f"Comparado ao diagnóstico anterior do mesmo ativo: {t.get('Melhorou', 0)} melhorou, "
                      f"{t.get('Piorou', 0)} piorou, {t.get('Igual', 0)} igual.")
    elif ultimo:
        frases.append('Ainda não há dois diagnósticos do mesmo ativo para comparar: corrija e rode de novo.')
    if ind['correcoes_verificadas']:
        frases.append(f"{ind['correcoes_verificadas']} correção(ões) comprovada(s) por nova verificação e revisão.")
    if ind['acoes_vencidas']:
        frases.append(f"{ind['acoes_vencidas']} ação(ões) com prazo vencido.")
    if ind['subcategorias_avaliadas'] < ind['subcategorias_total']:
        falta = ind['subcategorias_total'] - ind['subcategorias_avaliadas']
        frases.append(f'Avaliação do NIST CSF 2.0: {falta} de {ind["subcategorias_total"]} subcategorias ainda '
                      'sem avaliação (sem avaliação não é o mesmo que sem problema).')
    return frases
