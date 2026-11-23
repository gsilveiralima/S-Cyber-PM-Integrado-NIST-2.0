"""Testes do adicionar_certificado.py (inclusão na lista de certificados autorizados)."""
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))

import adicionar_certificado as A  # noqa: E402


def lista(caminho):
    texto = caminho.read_text(encoding='utf-8')
    bloco = re.search(r'CERTIFICADOS_AUTORIZADOS\s*=\s*\[(.*?)\n\]', texto, re.S).group(1)
    return re.findall(r'"([0-9A-F]{40})"', bloco)


class AdicionarTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.app = Path(self.tmp.name) / 'appSCyberPM.py'
        shutil.copy(BASE / 'appSCyberPM.py', self.app)
        self.antes = lista(self.app)

    def tearDown(self):
        self.tmp.cleanup()

    def test_inclui_e_nao_repete(self):
        novo = 'ab cd ' + 'C' * 36
        self.assertTrue(A.adicionar(novo, 'SGT Teste', self.app))
        self.assertEqual(lista(self.app), self.antes + ['ABCD' + 'C' * 36])
        self.assertFalse(A.adicionar('abcd' + 'c' * 36, '', self.app))
        compile(self.app.read_text(encoding='utf-8'), 'appSCyberPM.py', 'exec')   # continua Python válido

    def test_recusa_invalido(self):
        with self.assertRaises(ValueError):
            A.adicionar('123', '', self.app)
        with self.assertRaises(ValueError):
            A.adicionar('"; import os #' + 'A' * 40, '', self.app)   # sobra texto além dos 40 hex
        self.assertEqual(lista(self.app), self.antes)

    def test_comentario_nao_quebra_linha(self):
        A.adicionar('D' * 40, 'linha1\nimport os', self.app)
        texto = self.app.read_text(encoding='utf-8')
        self.assertIn('# linha1 import os', texto)
        compile(texto, 'appSCyberPM.py', 'exec')


if __name__ == '__main__':
    unittest.main()
