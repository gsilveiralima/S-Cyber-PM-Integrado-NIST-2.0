"""Correções da auditoria S-Cyber 2.0 (Fase 1/2): regressões verificáveis."""
import hashlib
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nist_intelligence import core, crypto  # noqa: E402


class ChaveAntesDeGravarTests(unittest.TestCase):
    """Com o certificado errado (ou sem chave), o banco cifrado não pode ser alterado."""

    def test_chave_errada_nao_altera_o_arquivo(self):
        with tempfile.TemporaryDirectory() as tmp:
            arq = Path(tmp) / 'nist.db'
            db = core.connect(arq, crypto.derive_key(os.urandom(32)))
            core.save_risk(db, 'Risco de teste', 'Contas', 2, 2, 'PR')
            db.close()
            # simula um banco de versão anterior: sem uma tabela que a versão atual cria
            con = sqlite3.connect(arq)
            con.execute('DROP TABLE achado_log')
            con.commit()
            con.close()
            antes = hashlib.sha256(arq.read_bytes()).hexdigest()
            for chave in (crypto.derive_key(os.urandom(32)), None):
                with self.assertRaises(PermissionError):
                    core.connect(arq, chave)
            self.assertEqual(hashlib.sha256(arq.read_bytes()).hexdigest(), antes)
            con = sqlite3.connect(arq)
            tabelas = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            con.close()
            self.assertNotIn('achado_log', tabelas)


if __name__ == '__main__':
    unittest.main()


class RecuperacaoSemLicencaTests(unittest.TestCase):
    """S2: licença inválida não tira do titular o acesso aos próprios dados."""

    def setUp(self):
        import importlib
        from unittest import mock
        from test_seguranca import _STUBS
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self._p = mock.patch.dict(sys.modules, _STUBS)
        self._p.start()
        sys.modules['modRecursos'].pasta_dados = lambda: self.dir
        sys.modules.pop('formOpcoes', None)
        self.F = importlib.import_module('formOpcoes')
        self.chave = os.urandom(32)
        self.F._derivar_chave = lambda thumb: self.chave
        self.F._migrar_arquivo_antigo = lambda: None
        self.F.iniciar('A' * 40)
        self.F.definir_senhas_iniciais('Corujinha#Goias2026', 'Relatorio$Pdf2026x')
        self.db_path = self.dir / 'nist' / 'nist.db'
        db = core.connect(self.db_path, crypto.derive_key(self.chave))
        core.save_risk(db, 'Servidor sem atualização', 'Sistemas', 3, 3, 'PR')
        db.close()

    def tearDown(self):
        sys.modules.pop('formOpcoes', None)
        sys.modules.pop('modRecuperacao', None)
        self._p.stop()
        self.tmp.cleanup()

    def test_exporta_com_senha_e_registra(self):
        import modRecuperacao
        self.assertTrue(modRecuperacao.disponivel('expirada', self.dir))
        self.assertFalse(modRecuperacao.disponivel('invalida', self.dir))      # chave adulterada: não
        self.assertFalse(modRecuperacao.disponivel('expirada', self.dir / 'vazio'))
        with self.assertRaises(PermissionError):
            modRecuperacao.exportar(self.dir, 'A' * 40, 'senha errada', 'expirada', db_path=self.db_path)
        pasta = modRecuperacao.exportar(self.dir, 'A' * 40, 'Corujinha#Goias2026', 'expirada',
                                        db_path=self.db_path)
        self.assertIn('Servidor sem atualização', (pasta / 'risks.csv').read_text(encoding='utf-8-sig'))
        manifesto = (pasta / 'MANIFESTO.txt').read_text(encoding='utf-8')
        for arq in ('nist_backup_cifrado.db', 'risks.csv', 'achados.csv', 'audit.csv'):
            digest = hashlib.sha256((pasta / arq).read_bytes()).hexdigest()
            self.assertIn(f'{digest}  {arq}', manifesto)
        db = core.connect(self.db_path, crypto.derive_key(self.chave))
        self.assertEqual(core.audit_list(db)[0][3:5], ('Recuperação', 'Exportar com licença inválida'))
        db.close()
        # o backup exportado continua cifrado e abre com a mesma chave
        self.assertEqual(core.key_status(pasta / 'nist_backup_cifrado.db', crypto.derive_key(self.chave)), 'abre')


class ConsistenciaTests(unittest.TestCase):
    """M2/M3: dependências declaradas e versão com fonte única."""
    BASE = Path(__file__).resolve().parents[1]

    def test_versao_fonte_unica(self):
        import re
        for p in self.BASE.glob('*.py'):
            self.assertIsNone(re.search(r'^#  Versão\s+: \d', p.read_text(encoding='utf-8'), re.M), p.name)
        self.assertIn('from formAbout import APP_AUTOR, APP_COPYRIGHT, APP_NOME, APP_SUBTITULO, APP_VERSAO',
                      (self.BASE / 'gerarExe.py').read_text(encoding='utf-8'))

    def test_dependencias_declaradas(self):
        import ast
        import re
        decl = set()
        for nome in ('requirements.txt', 'requirements-opcionais.txt'):
            for linha in (self.BASE / nome).read_text(encoding='utf-8').splitlines():
                m = re.match(r'([A-Za-z0-9_.-]+)', linha.strip())
                if m and not linha.strip().startswith('#'):
                    decl.add(m.group(1).lower())
        modulo_pacote = {'PIL': 'pillow', 'win32com': 'pywin32', 'win32con': 'pywin32', 'win32gui': 'pywin32',
                         'win32print': 'pywin32', 'win32ui': 'pywin32', 'webview': 'pywebview',
                         'clr': 'pywebview', 'Microsoft': 'pywebview', 'PyInstaller': None}
        locais = {p.stem for p in self.BASE.glob('*.py')} | {'nist_intelligence', 'test_seguranca'}
        faltando = set()
        for p in list(self.BASE.glob('*.py')) + list((self.BASE / 'nist_intelligence').glob('*.py')):
            for n in ast.walk(ast.parse(p.read_text(encoding='utf-8'))):
                nomes = [a.name for a in n.names] if isinstance(n, ast.Import) else (
                    [n.module] if isinstance(n, ast.ImportFrom) and n.module and n.level == 0 else [])
                for nome in nomes:
                    raiz = nome.split('.')[0]
                    if raiz in sys.stdlib_module_names or raiz in locais:
                        continue
                    pacote = modulo_pacote.get(raiz, raiz.lower())
                    if pacote and pacote not in decl:
                        faltando.add(f'{p.name}: {raiz}')
        self.assertEqual(faltando, set())
        self.assertNotIn('numpy', decl)           # não é importado diretamente


class ScriptValidacaoTests(unittest.TestCase):
    def test_script_do_windows(self):
        arq = Path(__file__).resolve().parents[1] / 'validar_no_windows.ps1'
        bruto = arq.read_bytes()
        self.assertTrue(bruto.startswith(b'\xef\xbb\xbf') and not bruto.startswith(b'\xef\xbb\xbf' * 2))
        texto = bruto[3:].decode('ascii')               # PowerShell 5.1: só ASCII, BOM único
        for trecho in ('requirements-lock.txt', 'gerarExe.py', 'ISCC.exe', '--diagnostico', 'RESULTADO.txt'):
            self.assertIn(trecho, texto)
        self.assertNotIn('git push', texto)
