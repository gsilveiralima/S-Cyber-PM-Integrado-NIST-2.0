"""Testes da criptografia em repouso do banco NIST (v0.5)."""
import csv
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nist_intelligence import core, crypto, report  # noqa: E402

MASTER = os.urandom(32)          # simula a chave que o formOpcoes deriva do certificado
OUTRA = os.urandom(32)


class CriptografiaTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'nist.db'
        self.key = crypto.derive_key(MASTER)

    def tearDown(self):
        self.tmp.cleanup()

    def _popular(self, db):
        core.save_risk(db, 'Vazamento da planilha de efetivo', 'Dados pessoais', 3, 3, 'PR', 'PR.DS-01',
                       'Servidor interno', 'Pasta compartilhada aberta', owner='Sgt Gabriel')
        iid = core.save_incident(db, 'Phishing no e-mail funcional', 'Detecção', 'Conta do 1º BPM', 'Alta', True)
        core.advance_incident(db, iid, 'Contenção', 'Senha redefinida')
        arq = Path(self.tmp.name) / 'print.png'
        arq.write_bytes(b'img')
        eid = core.save_evidence(db, arq.name, core.sha256_file(arq), arq, 3, 'Print da mensagem', 'Sgt Gabriel', iid)
        core.custody_event(db, eid, 'Transferência', 'Cap Silva', 'Entregue à P2')
        core.save_sub_assessment(db, 'PR.AA-01', 1, 3, 'Seção de TI', '', 'Doc 123/2026', 'Implantar MFA')
        core.save_indicator(db, 'https://pastebin.example/abc', 'Lista de e-mails funcionais', 'Pendente')
        core.save_collection(db, {'host': 'PC-1BPM-07', 'user': 'PM\\gabriel', 'admin': False},
                             {'segredo': 'dados brutos'}, [{'id': 'x', 'title': 'Teste', 'status': 'OK',
                                                            'detail': 'Administradores: PM\\gabriel',
                                                            'subs': ['PR.AA-05']}])
        return eid

    def _arquivo_bruto(self):
        return self.path.read_bytes() + b''.join(p.read_bytes() for p in self.path.parent.glob('nist.db-*'))

    def test_textos_nao_ficam_em_claro_no_disco(self):
        db = core.connect(self.path, self.key)
        self._popular(db)
        db.close()
        bruto = self._arquivo_bruto()
        for texto in ('planilha de efetivo', 'Phishing', '1º BPM', 'Senha redefinida', 'print.png', 'Cap Silva',
                      'Entregue', 'Implantar MFA', 'pastebin', 'PC-1BPM-07', 'gabriel', 'dados brutos'):
            self.assertNotIn(texto.encode('utf-8'), bruto, texto)

    def test_leitura_com_a_chave_certa(self):
        db = core.connect(self.path, self.key)
        eid = self._popular(db)
        db.close()
        db = core.connect(self.path, crypto.derive_key(MASTER))
        self.assertEqual(core.risks(db)[0]['title'], 'Vazamento da planilha de efetivo')
        self.assertEqual(core.incidents(db)[0]['notes'], 'Conta do 1º BPM')
        self.assertEqual(core.custody_log(db, eid)[1][2:4], ('Cap Silva', 'Entregue à P2'))
        self.assertEqual(core.sub_assessments(db)['PR.AA-01']['action_note'], 'Implantar MFA')
        self.assertEqual(core.osint_list(db)[0][1], 'https://pastebin.example/abc')
        self.assertEqual(core.latest_findings(db)[0][2], 'PC-1BPM-07')
        self.assertEqual(core.verify_chain(db, 'custody_log'), (True, None))
        self.assertEqual(core.verify_chain(db, 'incident_log'), (True, None))
        self.assertTrue(core.recheck_evidence(db, eid, 'Sgt')[0])
        destino = Path(self.tmp.name) / 'riscos.csv'
        core.export_csv(db, 'risks', destino)
        with destino.open(encoding='utf-8-sig') as f:
            self.assertEqual(list(csv.reader(f, delimiter=';'))[1][1], 'Vazamento da planilha de efetivo')
        pdf = report.build(db, Path(self.tmp.name) / 'r.pdf')
        self.assertTrue(Path(pdf).read_bytes().startswith(b'%PDF'))
        db.close()

    def test_outro_certificado_e_recusado(self):
        core.connect(self.path, self.key).close()
        with self.assertRaises(PermissionError):
            core.connect(self.path, crypto.derive_key(OUTRA))

    def test_sem_chave_banco_cifrado_e_recusado(self):
        core.connect(self.path, self.key).close()
        with self.assertRaises(PermissionError):
            core.connect(self.path)

    def test_migra_banco_em_claro(self):
        db = core.connect(self.path)               # v0.4: sem chave
        eid = self._popular(db)
        self.assertFalse(db.encrypted)
        db.close()
        self.assertIn(b'Cap Silva', self._arquivo_bruto())
        db = core.connect(self.path, self.key)    # primeira abertura com o certificado
        self.assertTrue(db.encrypted)
        self.assertEqual(core.custody_log(db, eid)[1][2], 'Cap Silva')
        self.assertEqual(core.verify_chain(db, 'custody_log'), (True, None))   # hash sobre o texto em claro
        db.close()
        self.assertNotIn(b'Cap Silva', self._arquivo_bruto())

    def test_cifra_adulterada_e_detectada(self):
        db = core.connect(self.path, self.key)
        self._popular(db)
        db.close()
        raw = sqlite3.connect(self.path)
        nota = raw.execute('select note from custody_log where id=2').fetchone()[0]
        adulterada = nota[:-6] + ('AAAAA=' if not nota.endswith('AAAAA=') else 'BBBBB=')
        raw.execute('update custody_log set note=? where id=2', (adulterada,))
        raw.commit()
        raw.close()
        db = core.connect(self.path, self.key)
        self.assertEqual(core.custody_log(db, 1)[1][3], crypto.LOCKED)
        self.assertEqual(core.verify_chain(db, 'custody_log'), (False, 2))
        db.close()

    def test_chave_do_formopcoes_nunca_usada_direto(self):
        self.assertNotEqual(crypto.derive_key(MASTER), MASTER)
        with self.assertRaises(ValueError):
            crypto.derive_key(b'curta')


if __name__ == '__main__':
    unittest.main()
