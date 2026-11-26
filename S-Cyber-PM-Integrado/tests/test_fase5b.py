"""S-Cyber 2.0, Fase 5 (parte 2): e-mail do domínio pelo DNS público, OSV.dev e retentativa."""
import json
import os
import sys
import tempfile
import unittest
import urllib.parse
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))

from nist_intelligence import achados as A  # noqa: E402
from nist_intelligence import core, crypto, fontes  # noqa: E402
from nist_intelligence import diagnostico as D  # noqa: E402
from nist_intelligence import dominio as DM  # noqa: E402

KEY = crypto.derive_key(os.urandom(32))


def resposta(status=0, txt=(), mx=(), ad=False):
    ans = [{'name': 'x.', 'type': 16, 'TTL': 300, 'data': t} for t in txt]
    ans += [{'name': 'x.', 'type': 15, 'TTL': 300, 'data': m} for m in mx]
    return {'Status': status, 'AD': ad, 'Answer': ans} if ans else {'Status': status, 'AD': ad}


def dns_falso(zona):
    """zona: {(nome, tipo): resposta}. Registra as URLs pedidas."""
    pedidas = []

    def http(url, headers=None, timeout=20):
        pedidas.append(url)
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        chave = (q['name'][0], q['type'][0])
        if chave not in zona:
            raise fontes.FalhaFonte(fontes.INDISPONIVEL, 'Fonte indisponível: teste')
        return 200, json.dumps(zona[chave]).encode()
    http.pedidas = pedidas
    return http


def zona_fraca(d='empresa.com.br'):
    return {(d, 'TXT'): resposta(txt=['"v=spf1 include:_spf.exemplo.net ?all"']),
            (f'_dmarc.{d}', 'TXT'): resposta(status=3),
            (d, 'MX'): resposta(mx=['10 mx.exemplo.net.'])}


def zona_corrigida(d='empresa.com.br'):
    return {(d, 'TXT'): resposta(txt=['"v=spf1 include:_spf.exemplo.net " "-all"'], ad=True),
            (f'_dmarc.{d}', 'TXT'): resposta(txt=['"v=DMARC1; p=reject; rua=mailto:dmarc@empresa.com.br"'], ad=True),
            (d, 'MX'): resposta(mx=['10 mx.exemplo.net.'], ad=True)}


class NormalizarTests(unittest.TestCase):
    def test_aceita_url_email_e_maiusculas(self):
        self.assertEqual(DM.normalizar('https://WWW.Empresa.com.br/contato?x=1'), 'www.empresa.com.br')
        self.assertEqual(DM.normalizar('financeiro@empresa.com.br'), 'empresa.com.br')
        self.assertEqual(DM.normalizar('empresa.com.br.'), 'empresa.com.br')
        idn = DM.normalizar('Açaí.com.br')                       # vira punycode e volta igual
        self.assertTrue(idn.startswith('xn--'))
        self.assertEqual(idn.encode('ascii').decode('idna'), 'açaí.com.br')

    def test_recusa_o_que_nao_e_dominio(self):
        for ruim in ('', 'localhost', '10.0.0.1', 'a b.com', '-x.com', 'empresa..com'):
            with self.assertRaises(ValueError, msg=ruim):
                DM.normalizar(ruim)


class AvaliacaoTests(unittest.TestCase):
    def avaliar(self, zona, d='empresa.com.br'):
        return {r['id']: r for r in DM.evaluate(DM.coletar(d, dns_falso(zona)))}

    def test_dominio_fraco(self):
        r = self.avaliar(zona_fraca())
        self.assertEqual(set(r), {'dom_spf', 'dom_dmarc', 'dom_dnssec'})
        self.assertEqual(r['dom_spf']['status'], 'Atenção')            # ?all
        self.assertEqual(r['dom_dmarc']['status'], 'Falha')            # sem DMARC
        self.assertEqual(r['dom_dnssec']['status'], 'Atenção')
        for x in r.values():
            self.assertTrue(x['subs'] and all(s in core.SUB_CODES for s in x['subs']), x['id'])
            self.assertIsNot(D.recomendacao(x['id']), D.SEM_REGRA, x['id'])

    def test_dominio_corrigido_e_txt_em_partes(self):
        r = self.avaliar(zona_corrigida())
        self.assertEqual({k: v['status'] for k, v in r.items()},
                         {'dom_spf': 'OK', 'dom_dmarc': 'OK', 'dom_dnssec': 'OK'})
        self.assertIn('-all', r['dom_spf']['detail'])                 # as partes "a" "b" foram juntadas
        self.assertIn('dmarc@empresa.com.br', r['dom_dmarc']['detail'])

    def test_casos_de_spf_e_dmarc(self):
        d = 'empresa.com.br'
        casos = [
            ([], 'Falha'),                                                               # sem SPF
            (['"v=spf1 -all"', '"v=spf1 ~all"'], 'Falha'),                               # dois registros
            (['"v=spf1 +all"'], 'Falha'),
            (['"v=spf1 ip4:203.0.113.0/24"'], 'Atenção'),                               # sem "all"
            (['"v=spf1 ' + ' '.join(f'include:s{i}.exemplo.net' for i in range(11)) + ' -all"'], 'Atenção'),
            (['"google-site-verification=abc"', '"v=spf1 mx ~all"'], 'OK'),              # outros TXT são ignorados
        ]
        for txt, esperado in casos:
            zona = zona_corrigida()
            zona[(d, 'TXT')] = resposta(txt=txt)
            self.assertEqual(self.avaliar(zona)['dom_spf']['status'], esperado, txt)
        for dmarc, esperado in (('"v=DMARC1; p=none"', 'Atenção'), ('"v=DMARC1; p=quarantine; pct=50"', 'Atenção'),
                                ('"v=DMARC1; p=quarentena"', 'Falha'), ('"v=DMARC1; p=quarantine"', 'OK')):
            zona = zona_corrigida()
            zona[(f'_dmarc.{d}', 'TXT')] = resposta(txt=[dmarc])
            self.assertEqual(self.avaliar(zona)['dom_dmarc']['status'], esperado, dmarc)

    def test_falha_de_rede_e_dominio_inexistente_nunca_aprovam(self):
        r = self.avaliar({})                                          # DNS público fora do ar
        self.assertEqual({v['status'] for v in r.values()}, {'Indisponível'})
        r = self.avaliar({('naoexiste.com.br', 'TXT'): resposta(status=3)}, 'naoexiste.com.br')
        self.assertEqual({v['status'] for v in r.values()}, {'Indisponível'})
        self.assertIn('não existe', r['dom_spf']['detail'])

    def test_so_consultas_de_leitura_ao_dns_publico(self):
        http = dns_falso(zona_fraca())
        DM.coletar('empresa.com.br', http)
        self.assertEqual(len(http.pedidas), 3)
        self.assertTrue(all(u.startswith('https://dns.google/resolve?') for u in http.pedidas))


class FluxoDiagnosticoTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.db = core.connect(self.dir / 'n.db', KEY)
        self.db.definir_sessao('Sgt Teste', 'revisor')

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_do_dominio_fraco_a_melhoria_comprovada(self):
        # O ativo de domínio cadastrado antes pela organização é reaproveitado.
        existente = A.save_asset(self.db, 'Site da empresa', 'Domínio/Serviço web', 'empresa.com.br',
                                 criticality='Alta')
        r1 = D.registrar(self.db, DM.coletar('empresa.com.br', dns_falso(zona_fraca())), self.dir, dominio=True)
        self.assertEqual(r1['ativo']['id'], existente)
        self.assertTrue(r1['dominio'])
        self.assertEqual(r1['resumo']['situacoes'], {'OK': 0, 'Atenção': 2, 'Falha': 1, 'Indisponível': 0})
        dmarc = next(i for i in r1['itens'] if i['id'] == 'dom_dmarc')
        self.assertEqual(dmarc['prioridade'], 'Crítica')   # Falha 3 + criticidade Alta 2 + exposto 1 = 6
        self.assertEqual(len([a for a in A.achados(self.db, asset_id=existente)]), 3)
        origem = self.db.execute('SELECT source FROM collections WHERE id=?', (r1['coleta_id'],)).fetchone()[0]
        self.assertEqual(origem, 'Domínio (DNS público)')

        r2 = D.registrar(self.db, DM.coletar('empresa.com.br', dns_falso(zona_corrigida())), self.dir, dominio=True)
        self.assertEqual(r2['anterior_id'], r1['coleta_id'])
        self.assertEqual(r2['resumo']['tendencias'], {'Melhorou': 3})
        acoes = [x[3:5] for x in core.audit_list(self.db)]
        self.assertIn(('Diagnóstico', 'Executar'), acoes)

    def test_dominio_nao_se_mistura_com_o_computador(self):
        D.registrar(self.db, DM.coletar('empresa.com.br', dns_falso(zona_fraca())), self.dir, dominio=True)
        self.assertIsNone(D.ultimo(self.db))                 # "último diagnóstico local" continua só do PC


if __name__ == '__main__':
    unittest.main()


class OsvTests(unittest.TestCase):
    LOCK = ('# comentário\ncryptography==50.0.2\nPillow==13.0.0  # nota\npywin32==312 ; sys_platform == "win32"\n'
            'requests>=2.0\nrich[jupyter]==13.0.0\n')

    def test_le_so_versoes_exatas(self):
        self.assertEqual(fontes.pacotes_de_requirements(self.LOCK),
                         [('cryptography', '50.0.2'), ('pillow', '13.0.0'), ('pywin32', '312'), ('rich', '13.0.0')])

    def falso(self, vulns_por_pacote):
        consultas = []

        def post(url, dados, **kw):
            consultas.append((url, dados))
            return 200, json.dumps({'results': [
                {'vulns': [{'id': v} for v in vulns_por_pacote.get(q['package']['name'], [])]}
                for q in dados['queries']]}).encode()

        def baixar(url, headers=None, timeout=20):
            vid = url.rsplit('/', 1)[1]
            return 200, json.dumps({'id': vid, 'summary': f'Falha {vid}', 'aliases': ['CVE-2099-0001'],
                                    'affected': [{'package': {'name': 'pillow'},
                                                  'ranges': [{'events': [{'introduced': '0'},
                                                                         {'fixed': '13.0.1'}]}]}]}).encode()
        return post, baixar, consultas

    def test_correspondencia_com_versao_corrigida(self):
        post, baixar, consultas = self.falso({'pillow': ['GHSA-xxxx']})
        r = fontes.osv_pacotes(fontes.pacotes_de_requirements(self.LOCK), post=post, baixar=baixar)
        self.assertEqual(r.situacao, fontes.CORRESPONDENCIA)
        (item,) = r.itens
        self.assertEqual((item['pacote'], item['versao'], item['id'], item['corrigido_em']),
                         ('pillow', '13.0.0', 'GHSA-xxxx', '13.0.1'))
        self.assertEqual(item['apelidos'], ['CVE-2099-0001'])
        url, dados = consultas[0]
        self.assertEqual(url, 'https://api.osv.dev/v1/querybatch')
        # Só nome, ecossistema e versão saem do computador.
        self.assertEqual(set(dados['queries'][0]), {'package', 'version'})

    def test_sem_vulnerabilidade_e_falhas(self):
        post, baixar, _ = self.falso({})
        self.assertEqual(fontes.osv_pacotes([('pillow', '13.0.0')], post=post, baixar=baixar).situacao,
                         fontes.SEM_CORRESPONDENCIA)
        self.assertEqual(fontes.osv_pacotes([], post=post, baixar=baixar).situacao, fontes.SEM_CONFIGURACAO)

        def fora(url, dados, **kw):
            raise fontes.FalhaFonte(fontes.INDISPONIVEL, 'Fonte indisponível: teste')
        self.assertEqual(fontes.osv_pacotes([('pillow', '13.0.0')], post=fora).situacao, fontes.INDISPONIVEL)

        def torta(url, dados, **kw):
            return 200, b'{"results": []}'
        self.assertEqual(fontes.osv_pacotes([('pillow', '13.0.0')], post=torta).situacao, fontes.INDISPONIVEL)

    def test_comando_do_ci_nunca_aprova_sem_consultar(self):
        from nist_intelligence import dependencias
        with tempfile.TemporaryDirectory() as tmp:
            lock = Path(tmp) / 'lock.txt'
            lock.write_text(self.LOCK, encoding='utf-8')
            post, baixar, _ = self.falso({'pillow': ['GHSA-xxxx']})
            codigo, texto = dependencias.relatorio(lock, post, baixar)
            self.assertEqual(codigo, 1)
            self.assertIn('pillow 13.0.0: GHSA-xxxx', texto)
            post, baixar, _ = self.falso({})
            self.assertEqual(dependencias.relatorio(lock, post, baixar)[0], 0)

            def fora(url, dados, **kw):
                raise fontes.FalhaFonte(fontes.INDISPONIVEL, 'Fonte indisponível: teste')
            self.assertEqual(dependencias.relatorio(lock, fora)[0], 2)


@unittest.skipUnless(os.environ.get('SCYBER_FONTES_REAIS') == '1', 'consulta real só no CI (internet)')
class FontesReaisFase5bTests(unittest.TestCase):
    """Consulta REAL ao OSV.dev e ao Google Public DNS (no CI), para conferir o formato das respostas."""

    def test_osv_real(self):
        r = fontes.osv_pacotes([('jinja2', '2.4.1')])          # versão antiga com falhas públicas conhecidas
        print('OSV.dev (jinja2 2.4.1):', r.situacao, r.mensagem, [i['id'] for i in r.itens][:5])
        if r.situacao not in (fontes.INDISPONIVEL, fontes.LIMITE):
            self.assertEqual(r.situacao, fontes.CORRESPONDENCIA)
            self.assertTrue(all(i['id'] and i['pacote'] == 'jinja2' for i in r.itens))

    def test_dns_real(self):
        r = {x['id']: x for x in DM.evaluate(DM.coletar('google.com'))}
        print('Google DNS (google.com):', {k: v['status'] for k, v in r.items()})
        if r['dom_spf']['status'] != 'Indisponível':
            self.assertIn(r['dom_spf']['status'], ('OK', 'Atenção'))
            self.assertIn('v=spf1', r['dom_spf']['detail'])
        if r['dom_dmarc']['status'] != 'Indisponível':
            self.assertEqual(r['dom_dmarc']['status'], 'OK')     # google.com publica p=reject


class TlsWindowsNovoTests(unittest.TestCase):
    """Visto no VirtualBox: '[SSL: CERTIFICATE_VERIFY_FAILED] unable to get local issuer certificate'."""

    def test_contexto_soma_as_raizes_do_certifi_e_verifica_tudo(self):
        import ssl

        import certifi

        import modRede
        modRede._CONTEXTO = None
        ctx = modRede.contexto_tls()
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)          # nunca desliga a verificação
        self.assertTrue(ctx.check_hostname)
        so_certifi = ssl.create_default_context(cafile=certifi.where())
        self.assertGreaterEqual(ctx.cert_store_stats()["x509_ca"], so_certifi.cert_store_stats()["x509_ca"])
        self.assertIs(modRede.contexto_tls(), ctx)                     # criado uma vez só

    def test_listas_e_fontes_usam_o_contexto(self):
        import urllib.request
        from unittest import mock

        import modLicenca
        import modRede
        resposta = mock.MagicMock()
        resposta.__enter__.return_value.read.return_value = b"x"
        resposta.__enter__.return_value.status = 200
        with mock.patch.object(urllib.request, "urlopen", return_value=resposta) as abrir:
            modLicenca._baixar("revogacoes")
            fontes.http_get("https://exemplo")
        for chamada in abrir.call_args_list:
            self.assertIs(chamada.kwargs["context"], modRede.contexto_tls())
