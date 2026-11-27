"""Fase 6: primeiros passos na tela principal e Ribbon em 5 áreas."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

APP = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import modPrimeirosPassos as P  # noqa: E402
from nist_intelligence import core, crypto  # noqa: E402
from nist_intelligence import diagnostico as D  # noqa: E402
from test_fase4 import RAW_RUIM  # noqa: E402


class PrimeirosPassosTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.banco = Path(self.tmp.name) / 'nist.db'

    def test_ordem_e_proximo_passo(self):
        lista = P.passos(False, {}, None, self.banco)
        self.assertEqual([p['chave'] for p in lista],
                         ['termos', 'licenca', 'certificado', 'diagnostico', 'correcao', 'backup'])
        self.assertEqual(P.proximo(lista)['chave'], 'termos')
        self.assertFalse(self.banco.exists())                 # só lê: não cria o banco

    def test_diagnostico_conta_sem_abrir_os_textos_cifrados(self):
        db = core.connect(self.banco, crypto.derive_key(os.urandom(32)))
        db.definir_sessao('ana', 'usuario')
        D.executar(db, coletar=lambda thumb: RAW_RUIM)
        db.close()
        lista = P.passos(True, {'licenca_id': 'LIC-1', 'valida_ate': '2027-11-26'}, 'AB' * 20, self.banco)
        feitos = {p['chave']: p['feito'] for p in lista}
        self.assertTrue(feitos['diagnostico'])
        self.assertFalse(feitos['correcao'])
        self.assertEqual(P.proximo(lista)['chave'], 'correcao')
        (self.banco.parent / 'backups').mkdir()
        (self.banco.parent / 'backups' / 'nist_auto_20261127.db').write_bytes(b'')
        self.assertTrue({p['chave']: p['feito'] for p in P.passos(True, {}, None, self.banco)}['backup'])

    def test_banco_corrompido_nao_derruba_a_tela(self):
        self.banco.write_bytes(b'isto nao e sqlite')
        self.assertFalse({p['chave']: p['feito'] for p in P.passos(True, {}, None, self.banco)}['diagnostico'])


class CincoAreasTests(unittest.TestCase):
    def test_ribbon_em_cinco_areas(self):
        app = (APP / 'appSCyberPM.py').read_text(encoding='utf-8')
        areas = [linha.split('ribbon.aba("', 1)[1].split('"', 1)[0]
                 for linha in app.splitlines() if 'ribbon.aba("' in linha]
        self.assertEqual(areas, ['Visão geral', 'Operações', 'NIST Intelligence', 'Inteligência', 'Administração'])
        self.assertIn('ribbon.selecionar("Visão geral")', app)
        self.assertIn('nist.painel.iniciar_dominio()', app)
        self.assertIn('modPrimeirosPassos.criar_cartao(fundo, obter_passos', app)

    def test_botao_do_dominio_no_diagnostico(self):
        ui = (APP / 'nist_intelligence' / 'diagnostico_ui.py').read_text(encoding='utf-8')
        self.assertIn('def iniciar_dominio(self', ui)
        self.assertIn('return dm.coletar(dominio)', ui)                 # rede fora da thread da tela
        self.assertIn('dominio=dominio)', ui)                            # mesmo fluxo de registro
        self.assertIn('autorizado', ui)                                  # escopo autorizado explicado


if __name__ == '__main__':
    unittest.main()
