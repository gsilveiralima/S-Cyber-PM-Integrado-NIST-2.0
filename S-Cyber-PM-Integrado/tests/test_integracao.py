"""Testes da extensão NIST sem conectar a sistemas reais."""
import csv
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))   # funciona com "unittest discover -s tests" e com -I

from nist_intelligence import core  # noqa: E402
from nist_intelligence.bridge import ReadOnlySEIBridge, restricted_session, validate_endpoint  # noqa: E402
from nist_intelligence.core import (CATEGORIES, connect, csv_safe,  # noqa: E402
                                    delete_record, export_csv, save_incident, save_sub_assessment,
                                    save_indicator, save_risk, sha256_file)


class BancoTemporario(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db = connect(Path(self._tmp.name) / 'nist.db')

    def tearDown(self):
        self.db.close()
        self._tmp.cleanup()


class CatalogoTests(unittest.TestCase):
    def test_catalogo_nist(self):
        self.assertEqual(len(CATEGORIES), 22)
        self.assertEqual(len(set(code for code, _ in CATEGORIES)), 22)

    def test_dados_na_pasta_do_scyber(self):
        self.assertEqual(core.DATA.parent.name, 'SCyberPM')

    def test_hash(self):
        with tempfile.TemporaryDirectory() as p:
            file = Path(p) / 'hash.txt'
            file.write_bytes(b'abc')
            self.assertEqual(sha256_file(file), hashlib.sha256(b'abc').hexdigest())


class PersistenciaTests(BancoTemporario):
    def test_avaliacao_e_osint_local(self):
        save_sub_assessment(self.db, 'GV.OC-01', 2, 3, evidence_note='Referência', action_note='Ação')
        save_indicator(self.db, 'https://example.org/publico', 'Referência pública', 'Pendente')
        self.assertEqual(self.db.execute('select count(*) from sub_assessments').fetchone()[0], 1)
        self.assertEqual(self.db.execute('select count(*) from osint_indicators').fetchone()[0], 1)


    def test_validacoes(self):
        with self.assertRaises(ValueError):
            save_risk(self.db, '', 'Dados', 1, 1, 'GV')
        with self.assertRaises(ValueError):
            save_risk(self.db, 'R', 'Dados', 4, 1, 'GV')
        with self.assertRaises(ValueError):
            save_incident(self.db, 'x' * 3000, 'Pendente', '')
        with self.assertRaises(ValueError):
            save_indicator(self.db, 'http://inseguro.org', 'x', 'Pendente')

    def test_exclusao_somente_em_tabelas_permitidas(self):
        save_risk(self.db, 'Risco', 'Dados', 1, 1, 'GV')
        rid = self.db.execute('select id from risks').fetchone()[0]
        delete_record(self.db, 'risks', rid)
        self.assertEqual(self.db.execute('select count(*) from risks').fetchone()[0], 0)
        with self.assertRaises(ValueError):   # incidentes não são apagados: são encerrados
            delete_record(self.db, 'incidents', 1)
        with self.assertRaises(ValueError):
            delete_record(self.db, 'nist_assessments; DROP TABLE risks', 1)

    def test_csv_sem_injecao_de_formula(self):
        self.assertEqual(csv_safe('=HYPERLINK("http://x")'), '\'=HYPERLINK("http://x")')
        self.assertEqual(csv_safe('texto'), 'texto')
        self.assertEqual(csv_safe(5), 5)
        save_incident(self.db, '=cmd|"/c calc"!A1', 'Detecção', '+soma')
        destino = Path(self._tmp.name) / 'inc.csv'
        export_csv(self.db, 'incidents', destino)
        with destino.open(encoding='utf-8-sig', newline='') as f:
            linhas = list(csv.reader(f, delimiter=';'))
        self.assertTrue(linhas[1][1].startswith("'="))
        self.assertTrue(linhas[1][9].startswith("'+"))


class SEITests(unittest.TestCase):
    def test_endereco_sei_valido(self):
        self.assertEqual(validate_endpoint('https://sei.example.org/'), 'https://sei.example.org')
        for ruim in ('http://sei.example.org', 'https://u:senha@sei.example.org',
                     'https://sei.example.org/?a=1', ''):
            with self.assertRaises(ValueError):
                validate_endpoint(ruim)

    def _sessao(self):
        try:
            import requests  # noqa: F401
        except ImportError:
            self.skipTest('requests não instalado')
        return restricted_session('https://sei.example.org', 'Segredo#1')

    def test_bloqueia_outro_host(self):
        import requests
        s = self._sessao()
        with self.assertRaises(requests.RequestException):
            s.get('https://atacante.example.net/')

    def test_bloqueia_senha_na_url(self):
        import requests
        s = self._sessao()
        with self.assertRaises(requests.RequestException):
            s.get('https://sei.example.org/login', params={'senha': 'Segredo#1'})

    def test_porta_443_explicita_e_mesma_origem(self):
        from nist_intelligence.bridge import _origin
        self.assertEqual(_origin('https://SEI.example.org'), _origin('https://sei.example.org:443/x'))
        self.assertNotEqual(_origin('https://sei.example.org'), _origin('https://sei.example.org:8443'))

    def test_ponte_usa_cliente_injetado(self):
        class Falso:
            sessao = None
            def pesquisar(self, termo):
                return [{'numero': termo}]
        ponte = ReadOnlySEIBridge(client_factory=Falso)
        self.assertEqual(ponte.search('  123  '), [{'numero': '123'}])
        with self.assertRaises(ValueError):
            ponte.search('x' * 121)


class HospedeiroTests(unittest.TestCase):
    def test_host_continua_protegido_por_login_original(self):
        source = (BASE / 'appSCyberPM.py').read_text(encoding='utf-8')
        self.assertIn('SplashScreen(root, on_success=lambda: FormLogin(', source)
        self.assertIn('PainelNist(root, fundo, status, BASE_DIR)', source)
        nist = (BASE / 'modNist.py').read_text(encoding='utf-8')
        self.assertIn('from formNISTIntelligence import criar_painel', nist)

    def test_bridge_nao_executa_arquivo_por_caminho(self):
        source = (BASE / 'nist_intelligence' / 'bridge.py').read_text(encoding='utf-8')
        self.assertNotIn('.exec_module(', source)
        self.assertNotIn('import importlib', source)
        self.assertNotIn('import subprocess', source)


if __name__ == '__main__':
    unittest.main()
