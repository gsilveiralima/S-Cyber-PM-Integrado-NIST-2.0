"""Consistência do roteiro do Tour (análise estática: não abre janelas nem exige Pillow)."""
import ast
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]


def _arvore(nome):
    return ast.parse((BASE / nome).read_text(encoding="utf-8"))


def _passos():
    """(título, destaque, ação) de cada Passo(...) do ROTEIRO."""
    passos = []
    for no in ast.walk(_arvore("formTour.py")):
        if isinstance(no, ast.Call) and getattr(no.func, "id", None) == "Passo":
            kw = {k.arg: k.value.value for k in no.keywords
                  if isinstance(k.value, ast.Constant)}
            passos.append((no.args[0].value, kw.get("destaque"), kw.get("acao")))
    return passos


def _chaves_do_dict(arvore, alvo):
    for no in ast.walk(arvore):
        if isinstance(no, ast.Assign) and any(getattr(t, "id", None) == alvo for t in no.targets) \
                and isinstance(no.value, ast.Dict):
            return {k.value for k in no.value.keys if isinstance(k, ast.Constant)}
    return set()


class RoteiroDoTour(unittest.TestCase):
    def test_acoes_existem_no_aplicativo(self):
        acoes = _chaves_do_dict(_arvore("appSCyberPM.py"), "acoes")
        self.assertTrue(acoes)
        internas = {"percorrer_ribbon"}
        for titulo, _, acao in _passos():
            if acao:
                self.assertIn(acao.partition(":")[0], acoes | internas, titulo)

    def test_destaques_tem_icone(self):
        icones = _chaves_do_dict(_arvore("modRibbon.py"), "DESENHOS") | {"coruja"}   # coruja: imagem, não desenho
        self.assertTrue(icones)
        for titulo, destaque, _ in _passos():
            if destaque:
                self.assertIn(destaque, icones, titulo)

    def test_abas_nist_do_tour_existem_no_painel(self):
        fonte = (BASE / "nist_intelligence" / "main.py").read_text(encoding="utf-8")
        abas = [a for _, _, a in _passos() if a and a.startswith("nist_aba:")]
        self.assertTrue(abas)
        for acao in abas:
            self.assertIn(f"add_tab('{acao.partition(':')[2]}')", fonte, acao)


if __name__ == "__main__":
    unittest.main()
