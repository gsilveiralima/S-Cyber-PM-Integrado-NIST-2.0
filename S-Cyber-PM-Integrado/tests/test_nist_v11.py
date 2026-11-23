"""Testes da v1.1: trilha de auditoria, coleta contínua, incidente ligado ao SEI e backup."""
import os
import sqlite3
import sys
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nist_intelligence import core, crypto  # noqa: E402

KEY = crypto.derive_key(os.urandom(32))


def _resultados(**status):
    return [{'id': k, 'title': k.upper(), 'status': v, 'detail': f'detalhe {k}',
             'subs': {'firewall': ['PR.IR-01'], 'bitlocker': ['PR.DS-01'], 'uac': ['PR.AA-05']}[k]}
            for k, v in status.items()]


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.path = self.dir / 'nist.db'
        self.db = core.connect(self.path, KEY)
        self.db.actor = 'agente (gsilv) — CN=S-Cyber-PM-NIST-2.0'

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()


class AuditoriaTests(Base):
    def test_registra_quem_fez_cada_alteracao(self):
        core.save_sub_assessment(self.db, 'PR.DS-01', 1, 3)
        core.save_risk(self.db, 'Vazamento', 'Dados', 3, 3, 'PR')
        iid = core.save_incident(self.db, 'Phishing', 'Detecção', '', 'Alta', True)
        core.advance_incident(self.db, iid, 'Contenção', 'Conta bloqueada')
        core.delete_record(self.db, 'risks', 1)
        core.log_event(self.db, 'Relatório', 'Gerar', '', 'relatorio.pdf')
        trilha = core.audit_list(self.db)
        self.assertEqual([(e[3], e[4]) for e in reversed(trilha)],
                         [('Avaliação', 'Salvar'), ('Risco', 'Registrar'), ('Incidente', 'Registrar'),
                          ('Incidente', 'Fase'), ('Risco', 'Excluir'), ('Relatório', 'Gerar')])
        self.assertTrue(all(e[2] == self.db.actor for e in trilha))
        self.assertEqual(core.verify_chain(self.db, 'audit_log'), (True, None))

    def test_quem_e_o_que_ficam_cifrados_e_adulteracao_aparece(self):
        core.save_indicator(self.db, 'https://pastebin.example/x', 'Lista vazada', 'Pendente')
        self.db.close()
        bruto = self.path.read_bytes()
        for texto in (b'gsilv', b'pastebin', b'Lista vazada'):
            self.assertNotIn(texto, bruto)
        raw = sqlite3.connect(self.path)
        raw.execute("UPDATE audit_log SET action='Nada' WHERE id=1")
        raw.commit()
        raw.close()
        self.db = core.connect(self.path, KEY)
        self.assertEqual(core.verify_chain(self.db, 'audit_log'), (False, 1))
        self.assertTrue(any('trilha de auditoria' in a for a, _ in core.alerts(self.db)))


class ColetaContinuaTests(Base):
    def test_comparacao_e_alerta_de_piora(self):
        self.assertTrue(core.collection_needed(self.db))
        core.save_collection(self.db, {'host': 'PC1'}, {}, _resultados(firewall='OK', bitlocker='Falha',
                                                                       uac='Indisponível'))
        core.save_collection(self.db, {'host': 'PC1'}, {}, _resultados(firewall='Falha', bitlocker='OK',
                                                                       uac='OK'))
        mudancas = core.compare_collections(self.db)
        self.assertEqual([(m['check'], m['change']) for m in mudancas],
                         [('firewall', 'piorou'), ('bitlocker', 'melhorou')])   # uac: antes sem dados
        self.assertTrue(any('FIREWALL piorou' in a for a, _ in core.alerts(self.db)))
        self.assertFalse(core.collection_needed(self.db))
        futuro = date.today() + timedelta(days=core.AUTO_COLLECT_DAYS)
        self.assertTrue(core.collection_needed(self.db, today=futuro))

    def test_aplicar_coleta_nao_sobrescreve_avaliacao_humana(self):
        core.save_sub_assessment(self.db, 'PR.IR-01', 3, 4, evidence_note='Firewall revisado pela P6')
        core.save_collection(self.db, {'host': 'PC1'}, {}, _resultados(firewall='Falha', bitlocker='Atenção',
                                                                       uac='OK'))
        criadas, divergencias = core.apply_findings(self.db)
        self.assertEqual(criadas, ['PR.AA-05', 'PR.DS-01'])
        self.assertEqual(divergencias, [('PR.IR-01', 3, 1, 'Falha')])
        dados = core.sub_assessments(self.db)
        self.assertEqual((dados['PR.DS-01']['current'], dados['PR.DS-01']['target']), (2, 3))
        self.assertIn('Coleta técnica de', dados['PR.AA-05']['evidence_note'])
        self.assertEqual(dados['PR.IR-01']['current'], 3)                 # intocada
        self.assertEqual(dados['PR.IR-01']['evidence_note'], 'Firewall revisado pela P6')
        self.assertEqual(core.apply_findings(self.db)[0], [])           # repetir não duplica


class SEITests(Base):
    def test_vinculo_do_incidente_ao_processo(self):
        iid = core.save_incident(self.db, 'Vazamento', 'Detecção')
        core.set_incident_sei(self.db, iid, '32800.123456/2026-11', 'Comunicação interna')
        self.assertEqual(core.incidents(self.db)[0]['sei_process'], '32800.123456/2026-11')
        self.assertIn('processo SEI 32800.123456/2026-11', core.incident_timeline(self.db, iid)[-1][2])
        self.assertEqual(core.verify_chain(self.db, 'incident_log'), (True, None))
        with self.assertRaises(ValueError):
            core.set_incident_sei(self.db, iid, "1; DROP TABLE x")
        with self.assertRaises(ValueError):
            core.set_incident_sei(self.db, 999, '12345')


class BackupTests(Base):
    def test_backup_e_restauracao(self):
        core.save_risk(self.db, 'Antes do backup', 'Dados', 2, 2, 'ID')
        copia = core.backup(self.db, self.dir / 'backup.db')
        core.save_risk(self.db, 'Depois do backup', 'Dados', 1, 1, 'ID')
        self.db.close()
        guardado = core.restore(copia, self.path, KEY)
        self.assertTrue(guardado.exists())
        self.db = core.connect(self.path, KEY)
        self.assertEqual([r['title'] for r in core.risks(self.db)], ['Antes do backup'])
        self.assertEqual(core.audit_list(self.db)[0][3:5], ('Backup', 'Restaurar'))
        for table in ('audit_log', 'incident_log', 'custody_log'):
            self.assertEqual(core.verify_chain(self.db, table), (True, None))

    def test_backup_de_outro_certificado_e_recusado(self):
        copia = core.backup(self.db, self.dir / 'backup.db')
        self.db.close()
        antes = self.path.read_bytes()
        with self.assertRaises(PermissionError):
            core.restore(copia, self.path, crypto.derive_key(os.urandom(32)))
        self.assertEqual(self.path.read_bytes(), antes)      # nada foi trocado
        self.db = core.connect(self.path, KEY)


if __name__ == '__main__':
    unittest.main()
