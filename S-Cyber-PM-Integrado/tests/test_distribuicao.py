"""2.0.6: listas assinadas também no repositório público de distribuição (o do código pode ficar
privado). O aplicativo baixa dos dois e fica com a melhor cópia que confere."""
import io
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

APP = Path(__file__).resolve().parents[1]
RAIZ = APP.parent
sys.path.insert(0, str(APP))

import modLicenca as L  # noqa: E402


def _http(code):
    return urllib.error.HTTPError("https://x", code, "x", {}, io.BytesIO(b""))


class DuasOrigensTests(unittest.TestCase):
    def test_enderecos(self):
        self.assertEqual(len(L.URLS_PUBLICACAO), 2)
        self.assertIn("/S-Cyber-Distribuicao/main/licencas/", L.URLS_PUBLICACAO[0])
        self.assertEqual(L.URLS_PUBLICACAO[1], L.URL_PUBLICACAO)

    def test_junta_as_copias_e_ignora_o_privado(self):
        def falso(base, nome, timeout=6):
            if "Distribuicao" in base:
                return b"da-distribuicao"
            raise _http(404)                     # repositório do código já privado
        with mock.patch.object(L, "_baixar_de", side_effect=falso):
            self.assertEqual(L._baixar("revogacoes"), [b"da-distribuicao"])

    def test_as_duas_respondem(self):
        with mock.patch.object(L, "_baixar_de", side_effect=lambda b, n, t=6: b.encode()):
            self.assertEqual(len(L._baixar("revogacoes")), 2)

    def test_sem_lista_em_nenhuma_e_http(self):
        with mock.patch.object(L, "_baixar_de", side_effect=_http(404)):
            with self.assertRaises(urllib.error.HTTPError):
                L._baixar("revogacoes")

    def test_sem_rede_e_erro_de_rede(self):
        with mock.patch.object(L, "_baixar_de", side_effect=urllib.error.URLError("offline")):
            with self.assertRaises(urllib.error.URLError):
                L._baixar("revogacoes")

    def test_publicacao_considera_as_duas_copias(self):
        pub = L.Publicacao(pasta_cache=APP / "nao-existe", pasta_pacote=APP / "nao-existe",
                           baixar=lambda nome: [b"a", b"b"], lembrar=False)
        self.assertEqual([c for _, c in pub._candidatos("revogacoes")], [b"a", b"b"])


class NomesAntigosSaemDaListaTests(unittest.TestCase):
    def test_publicar_retira_os_nomes_antigos(self):
        import tempfile

        import admin_licencas
        with tempfile.TemporaryDirectory() as tmp:
            adm = admin_licencas.Admin(pasta=Path(tmp) / "pub", assinador=lambda dados: b"x" * 64,
                                       thumb="B330B18E7E10C2F4F9182E911516A13DA0591CC9")
            antigo = {"tipo": "credenciamentos", "sequencia": 3, "revogados": [],
                      "certificados": [{"thumbprint": "AB" * 20, "titular": "Fulano", "papel": "usuario"}]}
            with mock.patch.object(adm, "_registrar") as registrar:
                doc = adm._sem_nomes(antigo)
            self.assertEqual(doc["certificados"][0]["titular"], "")
            self.assertEqual(doc["certificados"][0]["thumbprint"], "AB" * 20)
            self.assertIn("Fulano", registrar.call_args.kwargs["privado"])
            self.assertNotIn("Fulano", registrar.call_args.kwargs["detalhes"])
            self.assertEqual(antigo["certificados"][0]["titular"], "Fulano")      # não altera o original


class EspelhoNoCITests(unittest.TestCase):
    def test_workflow_espelha_listas_e_instaladores(self):
        wf = (RAIZ / ".github" / "workflows" / "distribuicao.yml").read_text(encoding="utf-8")
        self.assertIn("S-Cyber-PM-Integrado/licencas/**", wf)
        self.assertIn("DIST_TOKEN", wf)
        self.assertIn(L.REPOSITORIO_DISTRIBUICAO, wf)
        inst = (RAIZ / ".github" / "workflows" / "instalador.yml").read_text(encoding="utf-8")
        self.assertIn("DIST_TOKEN", inst)
        self.assertIn(L.REPOSITORIO_DISTRIBUICAO, inst)


if __name__ == "__main__":
    unittest.main()
