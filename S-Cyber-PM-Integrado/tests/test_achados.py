"""Fluxo ativo -> achado -> correção -> revisão, divergências, fontes abertas (com respostas
gravadas no formato oficial de cada API) e Pwned Passwords."""
import hashlib
import json
import os
import sys
import tempfile
import unittest
import unittest.mock
import urllib.error
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nist_intelligence import achados as A  # noqa: E402
from nist_intelligence import core, crypto, fontes, report  # noqa: E402

KEY = crypto.derive_key(os.urandom(32))
ANALISTA = 'sgt.analista (WIN) cert AAAA1111'
REVISOR = 'cap.revisor (WIN) cert BBBB2222'

KEV = {"title": "CISA Catalog of Known Exploited Vulnerabilities", "catalogVersion": "2026.11.20", "count": 2,
       "vulnerabilities": [
           {"cveID": "CVE-2024-3400", "vendorProject": "Palo Alto Networks", "product": "PAN-OS",
            "vulnerabilityName": "Palo Alto Networks PAN-OS Command Injection Vulnerability",
            "dateAdded": "2024-04-12", "shortDescription": "Command injection in GlobalProtect.",
            "requiredAction": "Apply mitigations per vendor instructions.", "dueDate": "2024-04-19",
            "knownRansomwareCampaignUse": "Unknown", "notes": "https://security.paloaltonetworks.com/CVE-2024-3400",
            "cwes": ["CWE-77"]},
           {"cveID": "CVE-2023-4966", "vendorProject": "Citrix", "product": "NetScaler ADC and NetScaler Gateway",
            "vulnerabilityName": "Citrix Bleed", "dateAdded": "2023-10-18", "shortDescription": "x",
            "requiredAction": "y", "dueDate": "2023-11-08", "knownRansomwareCampaignUse": "Known", "notes": ""}]}
BREACHES = [{"Name": "Exemplo", "Title": "Exemplo Serviços", "Domain": "exemplo.gov.br", "BreachDate": "2025-06-01",
             "AddedDate": "2025-07-02T10:00:00Z", "PwnCount": 1200, "DataClasses": ["Email addresses", "Passwords"]}]


def fake(respostas):
    """baixar(url, headers) -> resposta da tabela (prefixo da URL) ou exceção."""
    chamadas = []

    def baixar(url, headers=None):
        chamadas.append((url, headers or {}))
        for prefixo, resp in respostas.items():
            if url.startswith(prefixo):
                if isinstance(resp, Exception):
                    raise resp
                return resp
        raise fontes.FalhaFonte(fontes.INDISPONIVEL, 'sem rede')
    baixar.chamadas = chamadas
    return baixar


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.db = core.connect(self.dir / 'n.db', KEY)
        self.db.definir_sessao(ANALISTA, 'usuario')
        self.ev = self.dir / 'evidencias'

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def como(self, actor, papel):
        """Outro usuário = outra sessão autenticada (nova conexão ao mesmo banco)."""
        self.db.close()
        self.db = core.connect(self.dir / 'n.db', KEY)
        self.db.definir_sessao(actor, papel)


class SessaoTests(Base):
    def test_papel_vem_da_sessao_e_nao_muda(self):
        self.assertEqual(self.db.papel, 'usuario')
        with self.assertRaises(PermissionError):
            self.db.definir_sessao(REVISOR, 'administrador')
        with self.assertRaises(AttributeError):
            self.db.papel = 'administrador'
        nova = core.connect(self.dir / 'n.db', KEY)
        with self.assertRaises(ValueError):
            nova.definir_sessao('x', 'superusuario')
        nova.close()
        at = A.save_asset(self.db, 'Site', 'Domínio/Serviço web', 'exemplo.gov.br')
        with self.assertRaises(A.FlowError):
            A.authorize_asset(self.db, at, True)


class FluxoTests(Base):
    def test_fluxo_completo_com_auditoria_e_reinicio(self):
        fw = A.save_asset(self.db, 'Firewall da sede', 'Equipamento de rede', 'fw-sede', 'Seção de TI', 'Crítica',
                          'Palo Alto Networks', 'PAN-OS', '10.2.9')
        r = fontes.kev_por_cve(self.dir / 'cache', 'CVE-2024-3400', fake({fontes.KEV_URLS[0]: (200, json.dumps(KEV).encode())}))
        self.assertEqual(r.situacao, fontes.CORRESPONDENCIA)
        (aid, criado, _), = fontes.registrar_kev(self.db, fw, r, self.ev)
        self.assertTrue(criado)
        a = A.achado(self.db, aid)
        self.assertEqual((a['source'], a['ref'], a['event_date'], a['state']), ('CISA KEV', 'CVE-2024-3400',
                                                                              '2024-04-12', 'Novo'))
        ev = core.evidence(self.db, a['evidence_id'])                 # instantâneo da fonte com SHA-256
        self.assertEqual(hashlib.sha256(Path(ev['path']).read_bytes()).hexdigest(), ev['sha256'])
        with self.assertRaises(ValueError):                           # KEV: boletim do fabricante obrigatório
            A.confirm(self.db, aid, 'ID.RA-01', 'Crítica', 'Explorada ativamente', 'Sgt TI', '01/12/2026', 'Atualizar')
        A.confirm(self.db, aid, 'ID.RA-01', 'Crítica', 'Explorada ativamente e exposta à internet', 'Sgt TI',
                  '01/12/2026', 'Atualizar para 10.2.9-h1',
                  bulletin='https://security.paloaltonetworks.com/CVE-2024-3400')
        with self.assertRaises(ValueError):                           # correção sem evidência
            A.register_fix(self.db, aid, 'Atualizado', None)
        prova = core.save_evidence(self.db, 'versao.png', 'c' * 64, '', 1, 'print da versão')
        A.register_fix(self.db, aid, 'Atualizado para 10.2.9-h1', prova)
        with self.assertRaises(A.FlowError):                          # usuário comum não revisa
            A.review(self.db, aid, True, '')
        with self.assertRaises(A.FlowError):                          # quem corrigiu não revisa
            self.como(ANALISTA, 'revisor'); A.review(self.db, aid, True, '')
        self.como(REVISOR, 'revisor')
        with self.assertRaises(ValueError):
            A.review(self.db, aid, False, '')              # devolver exige parecer
        A.review(self.db, aid, False, 'Falta o print do hotfix')
        self.assertEqual(A.achado(self.db, aid)['state'], 'Confirmado')
        self.como(ANALISTA, 'usuario')
        A.register_fix(self.db, aid, 'Hotfix aplicado', prova)
        self.como(REVISOR, 'revisor')
        A.review(self.db, aid, True, 'Conferido')
        self.db.close()                                               # reinício: tudo continua rastreável
        self.db = core.connect(self.dir / 'n.db', KEY)
        a = A.achado(self.db, aid)
        self.assertEqual((a['state'], a['reviewer'], a['sub_code']), ('Encerrado', REVISOR, 'ID.RA-01'))
        acoes = [(r[1], r[2], r[4]) for r in A.timeline(self.db, aid)]
        self.assertEqual([x[1] for x in acoes], ['Registrar', 'Confirmar', 'Registrar correção', 'Devolver para ajuste',
                                                 'Registrar correção', 'Encerrar (revisão)'])
        self.assertEqual(acoes[-1], (REVISOR, 'Encerrar (revisão)', 'Encerrado'))
        self.assertTrue(core.verify_chain(self.db, 'achado_log')[0])

    def test_descarte_reabertura_e_incidente(self):
        site = A.save_asset(self.db, 'Portal', 'Domínio/Serviço web', 'exemplo.gov.br')
        aid, _, _ = A.observe(self.db, site, 'Manual', 'ACH-1', 'Formulário sem HTTPS')
        prova = core.save_evidence(self.db, 'x.png', 'e' * 64)
        with self.assertRaises(A.FlowError):                          # correção antes de confirmar
            A.register_fix(self.db, aid, 'x', prova)
        with self.assertRaises(ValueError):
            A.confirm(self.db, aid, 'XX.YY-01', 'Alta', 'x', 'y', '01/01/2027', 'z')
        A.discard(self.db, aid, 'Formulário desativado em 2025')
        with self.assertRaises(A.FlowError):
            A.discard(self.db, aid, 'de novo')
        A.reopen(self.db, aid, 'Voltou a responder')
        A.confirm(self.db, aid, 'PR.DS-02', 'Alta', 'Dados pessoais trafegam sem cifra', 'Ten Web', '10/12/2026',
                  'Ativar HTTPS')
        iid = A.escalate(self.db, aid, 'Alta', True)
        self.assertEqual(A.escalate(self.db, aid), iid)               # não duplica
        inc = [i for i in core.incidents(self.db) if i['id'] == iid][0]
        self.assertEqual((inc['subcategory'], inc['personal_data']), ('PR.DS-02', 1))
        core.set_incident_sei(self.db, iid, '202600001234567')
        self.assertTrue(inc['anpd_deadline'])

    def test_nova_coleta_divergente_preserva_a_decisao(self):
        pc = A.save_asset(self.db, 'Estação 01', 'Computador', 'PC-01')
        res = [{'id': 'firewall', 'title': 'Firewall', 'status': 'Falha', 'detail': 'desligado', 'subs': ['PR.IR-01']}]
        cid = core.save_collection(self.db, {'host': 'PC-01'}, {}, res)
        (aid, criado, _), = A.from_collection(self.db, cid, self.ev)
        self.assertTrue(criado)
        A.discard(self.db, aid, 'Equipamento será baixado')
        cid2 = core.save_collection(self.db, {'host': 'pc-01'}, {}, res)      # nova coleta: ainda falha
        (aid2, criado2, div), = A.from_collection(self.db, cid2, self.ev)
        self.assertEqual((aid2, criado2), (aid, False))
        a = A.achado(self.db, aid)
        self.assertEqual(a['state'], 'Descartado')                   # decisão humana preservada
        self.assertIn('ainda indica o problema', a['divergence'])
        self.assertEqual([p[0] for p in A.pending(self.db)], ['Divergência'])
        A.resolve_divergence(self.db, aid, 'Baixa confirmada pela Seção de Material')
        self.assertEqual(A.pending(self.db), [])
        self.assertEqual(A.from_collection(self.db, core.save_collection(self.db, {'host': 'PC-02'}, {}, res)), [])
        self.assertIsNotNone(pc)

    def test_pendencias_do_painel(self):
        at = A.save_asset(self.db, 'Servidor SEI', 'Servidor', 'srv-sei')
        a1, _, _ = A.observe(self.db, at, 'Manual', 'X1', 'Patch atrasado')
        A.confirm(self.db, a1, 'PR.PS-02', 'Alta', 'Patch crítico', 'Sgt A', (date.today() - timedelta(days=3))
                  .strftime('%d/%m/%Y'), 'Aplicar')
        a2, _, _ = A.observe(self.db, at, 'Manual', 'X2', 'Conta compartilhada')
        A.confirm(self.db, a2, 'PR.AA-01', 'Média', 'Sem rastreio', 'Sgt B', '01/01/2099', 'Contas nominais')
        A.register_fix(self.db, a2, 'Contas criadas', core.save_evidence(self.db, 'p.pdf', 'd' * 64))
        tipos = [(t, a['id']) for t, a in A.pending(self.db)]
        self.assertEqual(tipos, [('Ação vencida', a1), ('Aguardando verificação', a2)])
        self.assertEqual(A.by_owner(self.db), [('Sgt A', 1)])
        pdf = report.build(self.db, self.dir / 'r.pdf', 'Unidade', 'Sgt')
        self.assertGreater(Path(pdf).stat().st_size, 3000)


class FontesTests(Base):
    def test_situacoes_distintas(self):
        def erro(code, headers=None):
            return urllib.error.HTTPError('u', code, 'x', headers or {}, None)
        for exc, situacao in ((erro(401), fontes.ACESSO_RECUSADO), (erro(403), fontes.ACESSO_RECUSADO),
                              (erro(429, {'Retry-After': '7'}), fontes.LIMITE), (erro(503), fontes.INDISPONIVEL),
                              (urllib.error.URLError('dns'), fontes.INDISPONIVEL)):
            with unittest.mock.patch('urllib.request.urlopen', side_effect=exc):
                with self.assertRaises(fontes.FalhaFonte) as c:
                    fontes.http_get('https://exemplo')
                self.assertEqual(c.exception.situacao, situacao)
        with unittest.mock.patch('urllib.request.urlopen', side_effect=erro(404)):
            self.assertEqual(fontes.http_get('https://exemplo'), (404, b''))
        r = fontes.hibp_catalogo('exemplo.gov.br', fake({fontes.HIBP: (200, b'[]')}))
        self.assertEqual(r.situacao, fontes.SEM_CORRESPONDENCIA)
        r = fontes.hibp_catalogo('exemplo.gov.br', fake({}))
        self.assertEqual(r.situacao, fontes.INDISPONIVEL)

    def test_hibp_catalogo_e_dominio(self):
        site = A.save_asset(self.db, 'Portal', 'Domínio/Serviço web', 'exemplo.gov.br')
        r = fontes.hibp_catalogo('exemplo.gov.br', fake({fontes.HIBP + '/breaches': (200, json.dumps(BREACHES).encode())}))
        (aid, _, _), = fontes.registrar_hibp(self.db, site, r, self.ev)
        a = A.achado(self.db, aid)
        self.assertEqual((a['ref'], a['event_date']), ('Exemplo', '2025-06-01'))
        self.assertIn('Passwords', a['observation'])
        ativo = A.asset(self.db, site)
        self.assertEqual(fontes.hibp_dominio(self.db, ativo).situacao, fontes.SEM_CONFIGURACAO)
        with self.assertRaises(A.FlowError):
            fontes.definir_credencial(self.db, 'hibp', 'k' * 32)
        self.como(ANALISTA, 'administrador'); fontes.definir_credencial(self.db, 'hibp', 'k' * 32)
        r = fontes.hibp_dominio(self.db, ativo, fake({}))
        self.assertEqual(r.situacao, fontes.ACESSO_RECUSADO)          # ativo não autorizado
        A.authorize_asset(self.db, site, True)
        resp = fake({fontes.HIBP + '/breacheddomain/exemplo.gov.br': (200, json.dumps(
            {'fulano': ['Exemplo'], 'beltrano': ['Exemplo', 'Outro']}).encode())})
        r = fontes.hibp_dominio(self.db, A.asset(self.db, site), resp)
        self.assertEqual(resp.chamadas[0][1]['hibp-api-key'], 'k' * 32)
        contas = {i['Name']: i['contas'] for i in r.itens}
        self.assertEqual(contas, {'Exemplo': ['b***@exemplo.gov.br', 'f***@exemplo.gov.br'],
                                  'Outro': ['b***@exemplo.gov.br']})
        fontes.registrar_hibp(self.db, site, r, self.ev)
        texto = json.dumps([A.achado(self.db, x['id']) for x in A.achados(self.db)], ensure_ascii=False)
        self.assertNotIn('fulano@', texto)                            # e-mails sempre mascarados
        self.assertNotIn('k' * 32, json.dumps(core.audit_list(self.db), ensure_ascii=False))
        raw = (self.dir / 'n.db').read_bytes()
        self.assertNotIn(b'k' * 32, raw)                              # credencial cifrada no banco

    def test_github_secret_scanning(self):
        repo = A.save_asset(self.db, 'Repositório do app', 'Repositório', 'pmgo/app')
        self.como(ANALISTA, 'administrador'); A.authorize_asset(self.db, repo, True)
        self.assertEqual(fontes.github_alertas(self.db, A.asset(self.db, repo)).situacao, fontes.SEM_CONFIGURACAO)
        fontes.definir_credencial(self.db, 'github', 'ghp_teste')
        alerta = {"number": 7, "state": "open", "secret_type": "aws_access_key_id",
                  "secret_type_display_name": "Amazon AWS Access Key ID", "created_at": "2026-11-01T10:00:00Z",
                  "html_url": "https://github.com/pmgo/app/security/secret-scanning/7", "validity": "active",
                  "secret": None}
        resp = fake({fontes.GITHUB_API: (200, json.dumps([alerta]).encode())})
        r = fontes.github_alertas(self.db, A.asset(self.db, repo), resp)
        self.assertIn('hide_secret=true', resp.chamadas[0][0])
        self.assertEqual(resp.chamadas[0][1]['Authorization'], 'Bearer ghp_teste')
        self.assertNotIn('secret', r.itens[0])                       # o segredo nunca é guardado
        (aid, _, _), = fontes.registrar_github(self.db, repo, r, self.ev)
        self.assertEqual(A.achado(self.db, aid)['ref'], 'alerta #7')
        # a mesma ocorrência consultada de novo, agora resolvida, não cria outro achado
        alerta2 = dict(alerta, state='resolved', resolution='revoked')
        r2 = fontes.github_alertas(self.db, A.asset(self.db, repo), fake({fontes.GITHUB_API: (200, json.dumps([alerta2]).encode())}))
        (aid2, criado, div), = fontes.registrar_github(self.db, repo, r2, self.ev)
        self.assertEqual((aid2, criado), (aid, False))
        self.assertIn('não indica mais', div)
        r3 = fontes.github_alertas(self.db, A.asset(self.db, repo), fake({fontes.GITHUB_API: fontes.FalhaFonte(
            fontes.ACESSO_RECUSADO, 'HTTP 403')}))
        self.assertEqual(r3.situacao, fontes.ACESSO_RECUSADO)

    def test_kev_por_produto_e_cache(self):
        baixar = fake({fontes.KEV_URLS[0]: (200, json.dumps(KEV).encode())})
        r = fontes.kev_por_produto(self.dir / 'c', 'citrix', 'netscaler', baixar)
        self.assertEqual([v['cveID'] for v in r.itens], ['CVE-2023-4966'])
        fontes.kev_por_cve(self.dir / 'c', 'CVE-2023-4966', baixar)
        self.assertEqual(len(baixar.chamadas), 1)                    # segunda consulta usa o cache do dia
        with self.assertRaises(ValueError):
            fontes.kev_por_cve(self.dir / 'c', 'cve-x', baixar)
        r = fontes.kev_por_cve(self.dir / 'vazio', 'CVE-2024-3400', fake({}))
        self.assertEqual(r.situacao, fontes.INDISPONIVEL)

    def test_pwned_passwords_k_anonimato(self):
        senha = 'Corujinha#Goias2026'
        sha1 = hashlib.sha1(senha.encode()).hexdigest().upper()
        corpo = f'0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n{sha1[5:]}:42\r\nFFFF:0\r\n'.encode()
        baixar = fake({fontes.PWNED_RANGE: (200, corpo)})
        self.assertEqual(fontes.senha_vazada(senha, baixar), (fontes.CORRESPONDENCIA, 42))
        url, headers = baixar.chamadas[0]
        self.assertTrue(url.endswith('/' + sha1[:5]))
        self.assertNotIn(sha1[5:], url)                              # o resto do hash não sai
        self.assertEqual(headers['Add-Padding'], 'true')
        self.assertEqual(fontes.senha_vazada('outra', fake({fontes.PWNED_RANGE: (200, corpo)}))[0],
                         fontes.SEM_CORRESPONDENCIA)
        self.assertEqual(fontes.senha_vazada(senha, fake({}))[0], fontes.INDISPONIVEL)


@unittest.skipUnless(os.environ.get('SCYBER_FONTES_REAIS') == '1', 'consulta real só no CI (internet)')
class FontesReaisTests(unittest.TestCase):
    """Primeira consulta REAL às fontes públicas (roda no Windows do CI)."""

    def test_catalogos_publicos(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = fontes.kev_por_cve(tmp, 'CVE-2024-3400')
            print('KEV:', r.situacao, r.mensagem, [v.get('vulnerabilityName') for v in r.itens])
            if r.situacao != fontes.INDISPONIVEL:
                self.assertEqual(r.situacao, fontes.CORRESPONDENCIA)
                self.assertEqual(r.itens[0]['vendorProject'], 'Palo Alto Networks')
        r = fontes.hibp_catalogo('adobe.com')
        print('HIBP catálogo:', r.situacao, r.mensagem, [(b['Name'], b['BreachDate']) for b in r.itens])
        if r.situacao not in (fontes.INDISPONIVEL, fontes.LIMITE):
            self.assertEqual(r.situacao, fontes.CORRESPONDENCIA)
            self.assertEqual(r.itens[0]['Name'], 'Adobe')
        situacao, n = fontes.senha_vazada('P@ssw0rd')
        print('Pwned Passwords (P@ssw0rd):', situacao, n)
        if situacao != fontes.INDISPONIVEL:
            self.assertEqual(situacao, fontes.CORRESPONDENCIA)
            self.assertGreater(n, 1000)


if __name__ == '__main__':
    unittest.main()


try:
    import tkinter  # noqa: F401
    TK = True
except ImportError:
    TK = False


class SenhaVazadaFormTests(unittest.TestCase):
    def test_formularios_consultam_pwned_passwords(self):
        base = Path(__file__).resolve().parents[1]
        self.assertIn('modSenhaVazada.pode_usar(acesso', (base / 'formTrocaSenha.py').read_text(encoding='utf-8'))
        self.assertIn('modSenhaVazada.pode_usar(nova', (base / 'formOpcoes.py').read_text(encoding='utf-8'))

    @unittest.skipUnless(TK, 'tkinter ausente')
    def test_recusa_senha_vazada_e_pergunta_sem_rede(self):
        import modSenhaVazada
        with unittest.mock.patch.object(modSenhaVazada, 'messagebox') as mb:
            self.assertFalse(modSenhaVazada.pode_usar('x', 'senha', None, lambda s: (fontes.CORRESPONDENCIA, 3)))
            self.assertTrue(modSenhaVazada.pode_usar('x', 'senha', None, lambda s: (fontes.SEM_CORRESPONDENCIA, 0)))
            mb.askyesno.return_value = False
            self.assertFalse(modSenhaVazada.pode_usar('x', 'senha', None, lambda s: (fontes.INDISPONIVEL, 0)))
