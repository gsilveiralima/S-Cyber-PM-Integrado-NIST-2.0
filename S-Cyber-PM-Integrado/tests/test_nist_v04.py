"""Testes das funções da v0.4: catálogo, maturidade, lacunas, LGPD, cadeias de hash e coleta técnica."""
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nist_intelligence import collector, core, report  # noqa: E402
from nist_intelligence.catalog import CATEGORIES, SUB_BY_CATEGORY, SUBCATEGORIES, function_of  # noqa: E402


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.db = core.connect(self.dir / 'n.db')

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()


class CatalogoTests(unittest.TestCase):
    def test_106_subcategorias_oficiais(self):
        codes = [c for c, _ in SUBCATEGORIES]
        self.assertEqual(len(codes), 106)
        self.assertEqual(len(set(codes)), 106)
        self.assertEqual(set(SUB_BY_CATEGORY), {c for c, _ in CATEGORIES})
        por_funcao = {f: sum(1 for c in codes if function_of(c) == f) for f in ('GV', 'ID', 'PR', 'DE', 'RS', 'RC')}
        self.assertEqual(por_funcao, {'GV': 31, 'ID': 21, 'PR': 22, 'DE': 11, 'RS': 13, 'RC': 8})
        # Identificadores retirados no CSF 2.0 não podem aparecer
        for removido in ('ID.AM-06', 'PR.DS-03', 'DE.CM-04', 'RS.AN-01', 'RC.IM-01'):
            self.assertNotIn(removido, codes)


class AvaliacaoTests(Base):
    def test_maturidade_e_plano(self):
        core.save_sub_assessment(self.db, 'PR.DS-01', 1, 3, 'Sgt', '31/12/2026', '', 'BitLocker')
        core.save_sub_assessment(self.db, 'PR.AA-01', 2, 3)
        core.save_sub_assessment(self.db, 'GV.PO-01', 3, 3)
        mat = core.maturity_by_function(self.db)
        self.assertEqual(mat['PR'][2:], (2, 22))
        self.assertAlmostEqual(mat['PR'][0], round(3 / 22, 2))
        self.assertEqual(mat['PR'][1], 3.0)
        plan = core.gap_plan(self.db, {'PR.AA-01': 'Falha'})
        # lacuna 2 (DS-01) empata com lacuna 1 × peso 2 da falha técnica (AA-01); desempata o prazo
        self.assertEqual([(p['sub'], p['priority']) for p in plan], [('PR.DS-01', 2), ('PR.AA-01', 2)])
        self.assertEqual(plan[0]['due_date'], '2026-12-31')
        with self.assertRaises(ValueError):
            core.save_sub_assessment(self.db, 'XX.YY-99', 1, 2)
        with self.assertRaises(ValueError):
            core.save_sub_assessment(self.db, 'PR.DS-01', 5, 2)
        with self.assertRaises(ValueError):
            core.save_sub_assessment(self.db, 'PR.DS-01', 1, 2, due_date='31-31-2026')

    def test_tiers(self):
        core.save_tier(self.db, 'GV', 1, 3)
        self.assertEqual(core.tiers(self.db), {'GV': (1, 3)})
        with self.assertRaises(ValueError):
            core.save_tier(self.db, 'GV', 0, 3)


class RiscoTests(Base):
    def test_residual_e_mapa(self):
        core.save_risk(self.db, 'R1', 'Dados', 3, 3, 'PR', 'PR.DS-01', res_likelihood=1, res_impact=2)
        core.save_risk(self.db, 'R2', 'Dados', 1, 2, 'ID', status='Aceito')
        self.assertEqual(core.heat_map(self.db)[2][2], 1)              # impacto 3 × prob. 3
        self.assertEqual(core.heat_map(self.db, residual=True)[1][0], 1)
        self.assertEqual(sum(map(sum, core.heat_map(self.db))), 1)       # aceitos ficam fora
        rid = self.db.execute("select id from risks where title='R1'").fetchone()[0]
        core.save_risk(self.db, 'R1 editado', 'Dados', 2, 2, 'PR', status='Tratado', risk_id=rid)
        self.assertEqual(self.db.execute('select title,status from risks where id=?', (rid,)).fetchone(),
                         ('R1 editado', 'Tratado'))


class IncidenteTests(Base):
    def test_dias_uteis(self):
        sexta = date(2026, 11, 20)
        self.assertEqual(core.add_business_days(sexta, 3), date(2026, 11, 25))

    def test_prazo_anpd_e_linha_do_tempo(self):
        iid = core.save_incident(self.db, 'Vazamento', 'Detecção', 'Planilha exposta', 'Alta', True, '20/11/2026')
        inc = core.incidents(self.db)[0]
        self.assertEqual(inc['anpd_deadline'], '2026-11-25')
        self.assertIn('Vence em 25/11/2026', core.anpd_status(inc, today=date(2026, 11, 23)))
        self.assertTrue(core.anpd_status(inc, today=date(2026, 11, 26)).startswith('VENCIDO'))
        self.assertTrue(any('ANPD' in a for a, _ in core.alerts(self.db, today=date(2026, 11, 26))))
        core.advance_incident(self.db, iid, 'Contenção', 'Link removido')
        core.mark_anpd_notified(self.db, iid, '24/11/2026')
        self.assertEqual(core.anpd_status(core.incidents(self.db)[0]), 'Comunicado em 24/11/2026')
        self.assertEqual(len(core.incident_timeline(self.db, iid)), 3)
        self.assertEqual(core.verify_chain(self.db, 'incident_log'), (True, None))
        sem_dados = core.save_incident(self.db, 'Spam', 'Detecção')
        self.assertEqual(core.anpd_status(core.incidents(self.db)[0]), 'Não se aplica')
        self.assertTrue(sem_dados)

    def test_adulteracao_detectada(self):
        iid = core.save_incident(self.db, 'A', 'Detecção')
        core.advance_incident(self.db, iid, 'Análise', 'nota')
        self.db.execute("update incident_log set note='alterado' where id=1")
        self.assertEqual(core.verify_chain(self.db, 'incident_log'), (False, 1))


class CustodiaTests(Base):
    def test_cadeia_e_reverificacao(self):
        arq = self.dir / 'prova.bin'
        arq.write_bytes(b'conteudo')
        eid = core.save_evidence(self.db, arq.name, core.sha256_file(arq), arq, arq.stat().st_size, 'Print', 'Sgt')
        core.custody_event(self.db, eid, 'Transferência', 'Sgt', 'Entregue ao cartório')
        self.assertEqual(core.recheck_evidence(self.db, eid, 'Sgt')[0], True)
        arq.write_bytes(b'alterado')
        self.assertEqual(core.recheck_evidence(self.db, eid, 'Sgt')[0], False)
        arq.unlink()
        self.assertIsNone(core.recheck_evidence(self.db, eid, 'Sgt')[0])
        self.assertEqual(len(core.custody_log(self.db, eid)), 5)
        self.assertEqual(core.verify_chain(self.db, 'custody_log'), (True, None))
        self.db.execute("delete from custody_log where id=2")          # apagar um elo também é detectado
        self.assertEqual(core.verify_chain(self.db, 'custody_log')[0], False)


class ColetaTests(Base):
    RAW = {
        'meta': {'host': 'PC01', 'user': 'PM\\sgt', 'admin': False},
        'defender': {'realtime': False, 'service': True, 'tamper': True, 'sigage': 2},
        'firewall': [{'name': 'Domain', 'enabled': True}, {'name': 'Public', 'enabled': True}],
        'uac': {'lua': 1, 'admin_prompt': 5, 'inactivity': 600},
        'rdp': {'deny': 0, 'nla': 0},
        'smb1': {'erro': 'Acesso negado'},
        'bitlocker': {'drive': 'C:', 'protection': 1},
        'hotfix': {'last': '2026-11-01', 'id': 'KB5'},
        'admins': ['Administrador'],
        'guest': {'enabled': True}, 'nopwd': [],
        'netaccounts': ['Forçar logoff: Nunca', 'Mín (dias): 0', 'Máx (dias): 42', 'Comprimento mínimo: 12',
                        'Histórico: 24', 'Limite de bloqueio: 5', 'Duração: 30', 'Janela: 30', 'Função: WORKSTATION'],
        'pslog': {'enabled': 1}, 'eventlog': {'status': 'Running'},
        'listening': [3389, 49664],
        'certificado': {'notafter': '2026-12-01', 'privatekey': True},
    }

    def test_avaliacao(self):
        res = {r['id']: r for r in collector.evaluate(self.RAW, today=date(2026, 11, 22))}
        self.assertEqual(res['defender']['status'], 'Falha')
        self.assertEqual(res['firewall']['status'], 'OK')
        self.assertEqual(res['rdp']['status'], 'Falha')          # RDP sem NLA
        self.assertEqual(res['smb1']['status'], 'Indisponível')  # sem admin não é falha
        self.assertEqual(res['bitlocker']['status'], 'OK')
        self.assertEqual(res['updates']['status'], 'OK')
        self.assertEqual(res['accounts']['status'], 'Falha')     # convidado ativo
        self.assertEqual(res['pwpolicy']['status'], 'OK')
        self.assertEqual(res['screenlock']['status'], 'OK')
        self.assertEqual(res['ports']['status'], 'Atenção')
        self.assertEqual(res['appcert']['status'], 'Atenção')    # vence em 9 dias
        for r in res.values():
            self.assertTrue(set(r['subs']) <= core.SUB_CODES, r['id'])

    def test_gravacao_e_relatorio(self):
        results = collector.evaluate(self.RAW, today=date(2026, 11, 22))
        core.save_collection(self.db, collector.meta(self.RAW), self.RAW, results)
        by_sub = core.findings_by_subcategory(self.db)
        self.assertEqual(by_sub['DE.CM-09'], 'Falha')
        core.save_sub_assessment(self.db, 'DE.CM-09', 1, 3)
        pdf = report.build(self.db, self.dir / 'r.pdf', 'Unidade', 'Sgt')
        self.assertTrue(Path(pdf).read_bytes().startswith(b'%PDF'))
        ok, motivo = report.protection_available()
        self.assertFalse(ok)          # fora do S-Cyber PM não há certificado validado
        self.assertTrue(motivo)


if __name__ == '__main__':
    unittest.main()
