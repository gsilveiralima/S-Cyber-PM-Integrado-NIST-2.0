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
