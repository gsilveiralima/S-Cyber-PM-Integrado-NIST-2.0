"""2.0.6: o que um produto vendável precisa — licença proprietária única, Termos de Uso e
Política de Privacidade (com aceite registrado), avisos de terceiros, marca neutra da
Business e nomes de clientes fora das listas públicas."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

APP = Path(__file__).resolve().parents[1]
RAIZ = APP.parent
sys.path.insert(0, str(APP))

import modLicenca  # noqa: E402
import modTermos  # noqa: E402


def _tk_disponivel():
    try:
        import tkinter  # noqa: F401
        return True
    except ImportError:
        return False


class LicencaUnicaTests(unittest.TestCase):
    def test_licenca_proprietaria_na_raiz(self):
        texto = (RAIZ / "LICENSE").read_text(encoding="utf-8")
        self.assertIn("todos os direitos reservados", texto)
        self.assertNotIn("Apache License", texto)
        self.assertIn("v2.0.5", texto)                  # versões anteriores continuam Apache 2.0
        self.assertTrue((RAIZ / "AUTORES.md").is_file())

    def test_cabecalhos_sem_restricao_antiga_e_nome_certo(self):
        for arq in [*APP.glob("*.py"), *APP.glob("nist_intelligence/*.py")]:
            texto = arq.read_text(encoding="utf-8")
            self.assertNotIn("Uso interno da instituição", texto, arq.name)
            self.assertNotIn("Silvieira", texto, arq.name)


class DocumentosLegaisTests(unittest.TestCase):
    def test_textos_existem_em_utf8_com_bom(self):
        for _, nome in modTermos.ARQUIVOS:
            bruto = (APP / "legal" / nome).read_bytes()
            self.assertTrue(bruto.startswith(b"\xef\xbb\xbf"), nome)     # o Inno Setup lê acentos certo
            self.assertGreater(len(bruto), 800, nome)
        termos = modTermos.texto("TERMOS_DE_USO.txt", APP / "legal")
        for trecho in ("somente leitura", "não altera nada sozinho", "não é certificado pelo NIST",
                       "Lei nº 9.609/1998"):
            self.assertIn(trecho, termos)
        politica = modTermos.texto("POLITICA_DE_PRIVACIDADE.txt", APP / "legal")
        for trecho in ("LGPD", "5 primeiros", "não envia telemetria", "AES-256-GCM"):
            self.assertIn(trecho, politica)

    def test_instalador_e_executavel_levam_os_textos(self):
        iss = (APP / "instalador" / "SCyberPM.iss").read_text(encoding="utf-8")
        self.assertIn(r"LicenseFile=..\legal\TERMOS_DE_USO.txt", iss)
        self.assertIn(r"InfoBeforeFile=..\legal\POLITICA_DE_PRIVACIDADE.txt", iss)
        self.assertIn("AppPublisher=Equipe S-Cyber", iss)
        self.assertNotIn("Polícia Militar", iss)
        gerar = (APP / "gerarExe.py").read_text(encoding="utf-8")
        self.assertIn("PASTA / 'legal'", gerar)
        ci = (RAIZ / ".github" / "workflows" / "instalador.yml").read_text(encoding="utf-8")
        self.assertIn("LICENCAS_DE_TERCEIROS.txt", ci)
        self.assertIn("-Filter 'S-Cyber.lnk'", ci)


class AceiteDosTermosTests(unittest.TestCase):
    def test_aceite_registrado_por_versao(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(modTermos.aceite(tmp))
            dados = modTermos.registrar_aceite(tmp, APP / "legal")
            self.assertEqual(modTermos.aceite(tmp)["sha256_textos"], dados["sha256_textos"])
            self.assertEqual(len(dados["sha256_textos"]), 64)
            # Termos novos: o aceite antigo deixa de valer
            with mock.patch.object(modTermos, "VERSAO_TERMOS", "2099-01-01"):
                self.assertIsNone(modTermos.aceite(tmp))
            registro = json.loads((Path(tmp) / modTermos.REGISTRO).read_text(encoding="utf-8"))
            self.assertEqual(registro["versao"], modTermos.VERSAO_TERMOS)

    def test_ja_aceito_nao_abre_janela(self):
        with tempfile.TemporaryDirectory() as tmp:
            modTermos.registrar_aceite(tmp, APP / "legal")
            with mock.patch.object(modTermos, "aceite", return_value={"versao": modTermos.VERSAO_TERMOS}), \
                    mock.patch.object(modTermos, "mostrar") as janela:
                self.assertTrue(modTermos.garantir_aceite(root=None))
                janela.assert_not_called()

    def test_recusar_nao_registra(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(modTermos, "_arquivo_registro", lambda _p=None: Path(tmp) / "a.json"), \
                    mock.patch.object(modTermos, "mostrar", return_value=False):
                self.assertFalse(modTermos.garantir_aceite(root=None))
            self.assertFalse((Path(tmp) / "a.json").exists())

    def test_abertura_pede_o_aceite_antes_de_tudo(self):
        app = (APP / "appSCyberPM.py").read_text(encoding="utf-8")
        main = app.split("def main():", 1)[1]
        self.assertLess(main.index("modTermos.garantir_aceite(root)"), main.index("BarraStatus(root)"))
        self.assertIn("Termos de Uso e Privacidade...", app)


class BusinessSemMarcaDaPMTests(unittest.TestCase):
    def test_recursos_so_da_pm(self):
        business = {"modalidade": "business"}
        for recurso in ("sei", "radio", "espiao"):
            self.assertFalse(modLicenca.recurso_liberado(business, recurso), recurso)
            self.assertTrue(modLicenca.recurso_liberado({"modalidade": "pm"}, recurso), recurso)
        self.assertTrue(modLicenca.recurso_liberado(business, "diagnostico"))

    @unittest.skipUnless(_tk_disponivel(), "tkinter indisponível")
    def test_sobre_da_business_sem_pm(self):
        import formAbout
        ident = formAbout.identidade("business")
        self.assertEqual(ident["nome"], "S-Cyber Business")
        self.assertEqual(ident["contato"], modLicenca.EMAIL_SUPORTE)
        for campo in ("descricao", "autor", "contato"):
            for termo in ("PMGO", "Polícia Militar", "goias.gov.br", "sem fins lucrativos"):
                self.assertNotIn(termo, ident[campo], campo)
        self.assertIn("não é certificado pelo NIST", ident["descricao"])
        self.assertEqual(formAbout.identidade("xyz"), formAbout.identidade("pm"))
        self.assertNotIn("Polícia Militar", formAbout.APP_AUTOR)       # executável neutro
        self.assertIn("S-Cyber Business", formAbout.texto_informacoes("business"))

    def test_titulos_das_janelas_neutros(self):
        import re
        for arq in APP.glob("*.py"):
            if arq.name == "formTour.py":
                continue
            achados = re.findall(r'title\(f?"S-Cyber PM', arq.read_text(encoding="utf-8"))
            self.assertEqual(achados, [], arq.name)


if __name__ == "__main__":
    unittest.main()
