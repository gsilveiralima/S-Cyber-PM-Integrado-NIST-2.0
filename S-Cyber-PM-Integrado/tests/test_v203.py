"""v2.0.3: versão única, S-Cyber Business sem SEI e abas do painel NIST em várias linhas.

Os testes de janela (Tk) rodam no CI do Windows; sem tkinter ou sem tela, são pulados."""
import ast
import sys
import tempfile
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))

import modLicenca  # noqa: E402
import versao  # noqa: E402
from nist_intelligence import core, fontes, report  # noqa: E402

try:
    import tkinter as tk
except ImportError:          # Linux sem o pacote python3-tk
    tk = None


def _texto(nome):
    return (BASE / nome).read_text(encoding='utf-8')


def _tk_ou_pula(caso):
    if tk is None:
        caso.skipTest('tkinter indisponível')
    try:
        raiz = tk.Tk()
    except tk.TclError:
        caso.skipTest('sem tela para abrir janelas')
    raiz.withdraw()
    caso.addCleanup(raiz.destroy)
    return raiz


class VersaoUnicaTests(unittest.TestCase):
    def test_painel_nist_usa_a_versao_do_produto(self):
        self.assertRegex(versao.APP_VERSAO, r'^\d+\.\d+\.\d+$')
        self.assertEqual(core.VERSION, versao.APP_VERSAO)

    def test_instalador_e_formabout_usam_a_mesma_versao(self):
        iss = _texto('instalador/SCyberPM.iss')
        self.assertIn(f'#define AppVersion "{versao.APP_VERSAO}"', iss)
        about = _texto('formAbout.py')
        self.assertIn('from versao import APP_VERSAO', about)
        self.assertNotRegex(about, r'(?m)^APP_VERSAO\s*=', 'a versão só pode ser definida no versao.py')

    def test_consultas_externas_nao_identificam_o_orgao(self):
        self.assertNotIn('PMGO', fontes.USER_AGENT)
        self.assertIn(versao.APP_VERSAO, fontes.USER_AGENT)


class BusinessSemSeiTests(unittest.TestCase):
    def test_licenca_business_nao_libera_sei(self):
        self.assertFalse(modLicenca.recurso_liberado({'modalidade': 'business'}, 'sei'))
        self.assertTrue(modLicenca.recurso_liberado({'modalidade': 'pm'}, 'sei'))
        self.assertTrue(modLicenca.recurso_liberado({}, 'sei'))      # licenças antigas: PM

    def test_relatorio_business_sem_coluna_sei(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = core.connect(Path(tmp) / 'nist.db')
            core.save_incident(db, 'Phishing no financeiro')
            incs = core.incidents(db)
            for sei in (True, False):
                rows, widths = report.incident_table(incs, sei)
                self.assertEqual('SEI' in rows[0], sei)
                self.assertEqual({len(r) for r in rows}, {len(widths)})
                self.assertEqual(rows[1][1], 'Phishing no financeiro')
                pdf = report.build(db, Path(tmp) / f'r_{sei}.pdf', 'Empresa Exemplo', 'Analista', sei=sei)
                self.assertTrue(Path(pdf).read_bytes().startswith(b'%PDF'))
            db.close()

    def test_janela_principal_esconde_o_sei_na_business(self):
        app = _texto('appSCyberPM.py')
        self.assertIn('def ocultar_integracoes_institucionais():', app)
        corpo = app.split('def mostrar_principal():', 1)[1]
        self.assertIn('ocultar_integracoes_institucionais()', corpo)
        funcao = app.split('def ocultar_integracoes_institucionais():', 1)[1].split('\n    def ', 1)[0]
        for item in ('"SEI - consulta pelo navegador..."', '"Consultas SEI"', 'root.unbind("<Control-i>")',
                     'botao_sei.pack_forget()', 'assistente.comandos'):
            self.assertIn(item, funcao)
        self.assertIn('institucional=_sei_liberado()', app)              # Tour sem os passos do SEI

    def test_painel_recebe_a_modalidade_da_licenca(self):
        arvore = ast.parse(_texto('formNISTIntelligence.py'))
        chamadas = [n for n in ast.walk(arvore) if isinstance(n, ast.Call)
                    and getattr(n.func, 'id', None) == 'NISTPanel']
        self.assertEqual(len(chamadas), 1)
        self.assertEqual({k.arg for k in chamadas[0].keywords} >= {'sei', 'produto'}, True)

    def test_tour_business_sem_passos_do_sei(self):
        _tk_ou_pula(self)
        import formTour
        completo, business = formTour.roteiro(), formTour.roteiro(institucional=False)
        self.assertTrue(any('SEI' in p.titulo for p in completo))
        self.assertFalse(any('SEI' in p.titulo or p.destaque == 'sei' for p in business))
        self.assertEqual(len(completo) - len(business), 2)


class PainelNistTelaTests(unittest.TestCase):
    def _painel(self, **kw):
        raiz = _tk_ou_pula(self)
        from nist_intelligence.main import NISTPanel
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        painel = NISTPanel(raiz, db_path=str(Path(tmp.name) / 'nist.db'), **kw)
        self.addCleanup(painel.destroy)       # fecha o banco antes de apagar a pasta temporária
        return raiz, painel

    @staticmethod
    def _abas(painel):
        return [painel.tabs.tab(a, 'text') for a in painel.tabs.tabs()]

    def test_business_sem_sei_no_painel(self):
        _raiz, painel = self._painel(sei=False, produto='S-Cyber Business')
        self.assertNotIn('Consultas SEI', self._abas(painel))
        self.assertNotIn('SEI', painel.header_status.get())
        self.assertIn(f'v{versao.APP_VERSAO}', painel.header_status.get())
        self.assertNotIn('Processo SEI', list(painel.itree['displaycolumns']))

    def test_pm_mantem_o_sei(self):
        _raiz, painel = self._painel()
        self.assertIn('Consultas SEI', self._abas(painel))
        self.assertIn('Conexão SEI', painel.header_status.get())

    def test_abas_quebram_linha_em_tela_pequena(self):
        raiz, painel = self._painel(sei=False, produto='S-Cyber Business')
        barra = painel.barra_abas
        self.assertEqual(list(barra.botoes), list(painel.tabs.tabs()))
        painel.pack(fill='both', expand=True)
        raiz.deiconify()
        raiz.geometry('800x600')
        raiz.update()
        linhas = {b.winfo_y() for b in barra.botoes.values()}
        self.assertGreater(len(linhas), 1, 'em 800 px as abas precisam ocupar mais de uma linha')
        for botao in barra.botoes.values():                       # nenhuma aba cortada
            self.assertLessEqual(botao.winfo_x() + botao.winfo_reqwidth(), barra.winfo_width())
        # clicar numa aba da barra seleciona a aba do Notebook (e o contrário marca a barra)
        alvo = painel.tabs.tabs()[3]
        barra.botoes[alvo].event_generate('<Button-1>')
        raiz.update()
        self.assertEqual(painel.tabs.select(), alvo)
        self.assertEqual(barra.botoes[alvo].cget('bg'), barra.ATIVA)


if __name__ == '__main__':
    unittest.main()
