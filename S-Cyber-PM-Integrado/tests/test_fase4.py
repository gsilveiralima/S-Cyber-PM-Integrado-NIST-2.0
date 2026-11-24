"""S-Cyber 2.0, Fase 4: Diagnóstico Inteligente em um clique e Corujinha transparente (S7)."""
import ast
import copy
import os
import sys
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))

from nist_intelligence import achados as A  # noqa: E402
from nist_intelligence import collector, core, crypto  # noqa: E402
from nist_intelligence import diagnostico as D  # noqa: E402

KEY = crypto.derive_key(os.urandom(32))
HOJE = date.today()

# Coleta bruta no formato do PowerShell (collector._PS), com problemas reais de configuração
RAW_RUIM = {
    'meta': {'host': 'PC-TESTE', 'user': 'PC-TESTE\\ana', 'admin': True},
    'defender': {'realtime': True, 'service': True, 'tamper': True, 'sigage': 1, 'behavior': True},
    'firewall': [{'name': 'Domain', 'enabled': True}, {'name': 'Private', 'enabled': True},
                 {'name': 'Public', 'enabled': False}],
    'uac': {'lua': 1, 'admin_prompt': 5, 'inactivity': 600},
    'rdp': {'deny': 0, 'nla': 0},
    'smb1': {'enabled': True},
    'bitlocker': {'drive': 'C:', 'protection': 0},
    'secureboot': {'enabled': True},
    'hotfix': {'last': (HOJE - timedelta(days=10)).isoformat(), 'id': 'KB5000001'},
    'admins': ['PC-TESTE\\ana'],
    'guest': {'enabled': False}, 'nopwd': [],
    'netaccounts': ['a: 0', 'b: 0', 'c: 42', 'd: 12', 'e: 5', 'f: 10', 'g: 30'],
    'pslog': {'enabled': 1}, 'eventlog': {'status': 'Running'},
    'smartscreen': {'policy': None, 'explorer': 'RequireAdmin'},
    'restorepoints': {'erro': 'Acesso negado'},
    'listening': [135, 445, 3389],
}


def corrigido():
    raw = copy.deepcopy(RAW_RUIM)
    raw['firewall'][2]['enabled'] = True
    raw['rdp'] = {'deny': 1, 'nla': 1}
    raw['smb1'] = {'enabled': False}
    raw['listening'] = [5040]                 # porta comum, fora da lista de serviços sensíveis
    return raw


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = core.connect(Path(self.tmp.name) / 'n.db', KEY)
        self.db.definir_sessao('ana (PC-TESTE)', 'usuario')
        self.ev = Path(self.tmp.name) / 'evidencias'

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def rodar(self, raw, **kw):
        return D.executar(self.db, evidence_folder=self.ev, coletar=lambda thumb: raw, **kw)


class DiagnosticoTests(Base):
    def test_um_clique_do_ativo_a_recomendacao(self):
        etapas = []
        r = self.rodar(RAW_RUIM, progresso=lambda n, e: etapas.append(e))
        self.assertEqual(etapas, list(D.ETAPAS))
        # Ativo criado automaticamente para este computador
        self.assertEqual(r['ativo']['identifier'], 'PC-TESTE')
        self.assertEqual(r['ativo']['kind'], 'Computador')
        por_id = {i['id']: i for i in r['itens']}
        # Problemas reais viraram achados (suspeita, avaliação pendente), com NIST e recomendação
        for check in ('firewall', 'rdp', 'smb1', 'bitlocker', 'ports'):
            item = por_id[check]
            self.assertIn(item['situacao'], ('Falha', 'Atenção'), check)
            self.assertTrue(item['achado_id'], check)
            self.assertEqual(item['estado'], 'Suspeita (avaliação pendente)')
            self.assertTrue(item['nist'] and all(s in core.SUB_CODES for s in item['nist']), check)
            for campo in ('risco', 'corrigir', 'permissao', 'verificar', 'referencia'):
                self.assertTrue(item['recomendacao'][campo], (check, campo))
        # Indisponível NUNCA é aprovado e não vira achado
        self.assertEqual(por_id['backup']['situacao'], 'Indisponível')
        self.assertEqual(por_id['backup']['estado'], D.INDISPONIVEL)
        self.assertIsNone(por_id['backup']['achado_id'])
        self.assertIsNone(por_id['backup']['prioridade'])
        self.assertEqual(r['resumo']['situacoes']['Indisponível'], 1)
        self.assertEqual(r['resumo']['verificadas'], r['resumo']['total'] - 1)
        # Itens OK não geram achado
        self.assertIsNone(por_id['defender']['achado_id'])
        self.assertEqual(por_id['defender']['estado'], D.OBSERVADO_OK)
        # Ordem por prioridade: o mais grave primeiro
        self.assertIn(r['itens'][0]['prioridade'], ('Crítica', 'Alta'))
        # Evidência: coleta gravada com SHA-256, auditoria registrada
        sha = self.db.execute('SELECT sha256 FROM collections WHERE id=?', (r['coleta_id'],)).fetchone()[0]
        self.assertEqual(len(sha), 64)
        self.assertIn(('Diagnóstico', 'Executar'), [(x[3], x[4]) for x in core.audit_list(self.db)])
        self.assertIsNone(r['anterior_id'])

    def test_nova_verificacao_compara_e_mostra_melhoria(self):
        primeiro = self.rodar(RAW_RUIM)
        segundo = self.rodar(corrigido())
        self.assertEqual(segundo['anterior_id'], primeiro['coleta_id'])
        tend = {c: t for c, _, _, _, t in segundo['comparacao']}
        for check in ('firewall', 'rdp', 'smb1', 'ports'):
            self.assertEqual(tend[check], 'Melhorou', check)
        self.assertEqual(tend['bitlocker'], 'Igual')
        self.assertEqual(tend['backup'], 'Igual')                 # indisponível nos dois: não é melhora
        self.assertGreaterEqual(segundo['resumo']['tendencias']['Melhorou'], 4)
        # Mesmo ativo e sem achados duplicados (deduplicação ativo + fonte + verificação)
        self.assertEqual(segundo['ativo']['id'], primeiro['ativo']['id'])
        refs = [a['ref'] for a in A.achados(self.db, asset_id=primeiro['ativo']['id'])]
        self.assertEqual(len(refs), len(set(refs)))

    def test_decisao_humana_prevalece_e_divergencia_aparece(self):
        r = self.rodar(RAW_RUIM)
        smb = next(i for i in r['itens'] if i['id'] == 'smb1')
        A.discard(self.db, smb['achado_id'], 'Equipamento legado homologado pela seção')
        r2 = self.rodar(RAW_RUIM)
        smb2 = next(i for i in r2['itens'] if i['id'] == 'smb1')
        self.assertEqual(smb2['estado'], 'Falso positivo (descartado com justificativa)')
        self.assertTrue(A.achado(self.db, smb2['achado_id'])['divergence'])   # a coleta ainda vê o problema

    def test_cancelar_nao_grava_nada(self):
        chamadas = []

        def cancelar():
            chamadas.append(1)
            return len(chamadas) >= 3          # cancela durante a coleta: o resultado é descartado

        with self.assertRaises(D.Cancelado):
            self.rodar(RAW_RUIM, cancelado=cancelar)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM collections').fetchone()[0], 0)
        self.assertEqual(A.assets(self.db), [])

    def test_ultimo_diagnostico_para_reabrir_o_painel(self):
        self.assertIsNone(D.ultimo(self.db))
        r = self.rodar(RAW_RUIM)
        u = D.ultimo(self.db)
        self.assertEqual(u['coleta_id'], r['coleta_id'])
        self.assertEqual([i['id'] for i in u['itens']], [i['id'] for i in r['itens']])


class PrioridadeTests(unittest.TestCase):
    def test_regra_documentada(self):
        self.assertEqual(D.prioridade('Falha', 'Crítica', 'smb1')[0], 'Crítica')     # 3+3+1
        self.assertEqual(D.prioridade('Falha', 'Média', 'smb1')[0], 'Alta')          # 3+1+1
        self.assertEqual(D.prioridade('Falha', 'Média', 'bitlocker')[0], 'Média')    # 3+1
        self.assertEqual(D.prioridade('Atenção', 'Baixa', 'updates')[0], 'Baixa')    # 2+0
        self.assertIsNone(D.prioridade('OK')[0])
        self.assertIsNone(D.prioridade('Indisponível')[0])
        self.assertIn('Pontuação', D.METODOLOGIA_PRIORIDADE)

    def test_toda_verificacao_do_coletor_tem_recomendacao(self):
        checks = {r['id'] for r in collector.evaluate(dict(RAW_RUIM, certificado={'notafter': '2030-01-01',
                                                                                  'privatekey': True}))}
        self.assertEqual(checks - set(D.RECOMENDACOES), set())
        self.assertTrue(D.EXPOSTOS <= set(D.RECOMENDACOES))

    def test_nao_inventa_conformidade(self):
        """Nada de 'conforme', 'aprovado' ou porcentagem de segurança no texto do diagnóstico."""
        texto = (BASE / 'nist_intelligence' / 'diagnostico.py').read_text(encoding='utf-8').lower()
        for proibido in ('100% seguro', 'certificado pelo nist', 'em conformidade'):
            self.assertNotIn(proibido, texto)


class CorujinhaTransparenteTests(unittest.TestCase):
    """S7: consentimento, privacidade por padrão e processos identificados (análise do código-fonte:
    o formCoruja precisa de tkinter e Windows para importar)."""

    def setUp(self):
        self.fonte = (BASE / 'formCoruja.py').read_text(encoding='utf-8')
        self.arvore = ast.parse(self.fonte)

    def test_nada_de_camera_tela_ou_internet_sem_consentimento(self):
        valor = next(ast.literal_eval(n.value) for n in ast.walk(self.arvore)
                     if isinstance(n, ast.Assign) and getattr(n.targets[0], 'id', '') == 'SEM_CONSENTIMENTO')
        self.assertEqual(valor, {'camera': False, 'tela': False, 'internet': False})
        self.assertIn('if CAPTURAR_CAMERA and opcoes.get("camera")', self.fonte)
        self.assertIn('if CAPTURAR_SITE and opcoes.get("internet")', self.fonte)
        self.assertIn('if not (CAPTURAR_TELA and self.opcoes.get("tela"))', self.fonte)
        self.assertIn('autorizada=capturas.opcoes.get("internet", False)', self.fonte)

    def test_pede_consentimento_antes_de_comecar(self):
        func = next(n for n in self.arvore.body if isinstance(n, ast.FunctionDef) and n.name == 'executar_corujinha')
        corpo = ast.get_source_segment(self.fonte, func)
        self.assertLess(corpo.index('pedir_consentimento(master)'), corpo.index('iniciar_coleta('))
        self.assertIn('return None', corpo)

    def test_animacao_nao_se_esconde_e_processos_tem_pid(self):
        self.assertNotIn('self.protecao = proteger_contra_captura(self.win)', self.fonte)
        self.assertIn('capturas.pids[n] = processos[-1].pid', self.fonte)
        self.assertIn('PowerShell PID', self.fonte)
        # Validação de 24/11: o cabeçalho da animação ainda dizia "protegida contra captura"
        self.assertNotIn('(protegida contra captura)', self.fonte)


class InterfaceTests(unittest.TestCase):
    """O botão de um clique existe na Ribbon, no menu e no painel; a aba usa o mesmo motor.
    (A interface é exercitada com Tk simulado no harness da tela; aqui, a ligação no código.)"""

    def test_ligacoes(self):
        main = (BASE / 'nist_intelligence' / 'main.py').read_text(encoding='utf-8')
        self.assertIn('class NISTPanel(DiagnosticoMixin, AchadosMixin, ttk.Frame)', main)
        self.assertIn("self.t_diag = self.add_tab('Diagnóstico')", main)
        self.assertIn('command=self.iniciar_diagnostico', main)          # botão na visão geral
        ui = (BASE / 'nist_intelligence' / 'diagnostico_ui.py').read_text(encoding='utf-8')
        self.assertIn('D.registrar(self.db, raw', ui)                      # banco só na thread da tela
        self.assertIn('return collector.run(thumb)', ui)                   # coleta na thread de trabalho
        self.assertIn('Confirma a verificação DESTE computador?', ui)   # escopo confirmado antes
        self.assertIn('Diagnóstico cancelado: nada foi gravado.', ui)
        app = (BASE / 'appSCyberPM.py').read_text(encoding='utf-8')
        self.assertIn('grupo_nist.botao("Diagnóstico\\ninteligente", "nist", diagnostico_nist', app)
        self.assertIn('command=diagnostico_nist', app)
        self.assertIn('self.painel.iniciar_diagnostico()', (BASE / 'modNist.py').read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main()
