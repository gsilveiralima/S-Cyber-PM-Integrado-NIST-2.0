"""Tela do administrador (admin_licencas_tela.py): pedidos, emissão sem PowerShell e envio ao GitHub."""
import importlib.util
import re
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

APP_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP_DIR))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import admin_licencas as AL  # noqa: E402
import modLicenca as L  # noqa: E402
from test_ativacao import Base  # noqa: E402

TEM_TK = importlib.util.find_spec("tkinter") is not None


class ResumoPedidoTests(Base):
    def test_reconhece_ativacao_mesmo_quebrada_pelo_whatsapp(self):
        pedido = self.pedido()
        quebrado = "\n".join(pedido[i:i + 40] for i in range(0, len(pedido), 40)) + "\n "
        r = AL.resumo_pedido(quebrado)
        self.assertEqual(r["tipo"], "ativacao")
        self.assertEqual(r["pedido"], pedido)
        self.assertIn(r["dados"]["instalacao"], r["texto"])
        self.assertEqual(L.ler_pedido(quebrado)["instalacao"], r["dados"]["instalacao"])

    def test_reconhece_certificado(self):
        inst = L.instalacao(self.inst_dir)
        r = AL.resumo_pedido(L.pedido_credenciamento("AB" * 20, "SD Fulano", inst))
        self.assertEqual(r["tipo"], "certificado")
        self.assertIn("SD Fulano", r["texto"])

    def test_recusa_o_que_nao_e_pedido(self):
        for ruim in ("", "olá", "SCPM-PEDIDO-ATIVACAO.!!!", "SCPM-PEDIDO-ATIVACAO.e30",   # {} sem dados
                     "SCPM1.abc"):
            with self.assertRaises(ValueError, msg=ruim):
                AL.resumo_pedido(ruim)

    def test_nome_do_arquivo(self):
        self.assertEqual(AL.nome_arquivo({"instalacao": "INST-ABC"}), "licenca_INST-ABC.sclic")


class GithubTests(unittest.TestCase):
    def test_pasta_de_zip_nao_tenta_enviar(self):
        with tempfile.TemporaryDirectory() as tmp:
            chamadas = []
            ok, texto = AL.publicar_no_github(Path(tmp) / "licencas", executar=lambda *a, **k: chamadas.append(a))
            self.assertFalse(ok)
            self.assertIn("ZIP", texto)
            self.assertEqual(chamadas, [])

    def resultado(self, codigo=0, saida=""):
        return subprocess.CompletedProcess([], codigo, saida, "")

    def test_envia_so_a_pasta_das_listas(self):
        with tempfile.TemporaryDirectory() as tmp:
            raiz = Path(tmp)
            (raiz / ".git").mkdir()
            pasta = raiz / "S-Cyber-PM-Integrado" / "licencas"
            pasta.mkdir(parents=True)
            feitos = []

            def executar(cmd, **kw):
                feitos.append(cmd)
                return self.resultado()
            ok, _ = AL.publicar_no_github(pasta, "Licenças: teste", executar)
            self.assertTrue(ok)
            self.assertEqual([c[3] for c in feitos], ["add", "commit", "push"])
            self.assertEqual(feitos[0][-1], str(Path("S-Cyber-PM-Integrado") / "licencas"))
            self.assertIn("--", feitos[1])                      # commit só dessa pasta

    def test_nada_novo_e_push_recusado(self):
        with tempfile.TemporaryDirectory() as tmp:
            raiz = Path(tmp)
            (raiz / ".git").mkdir()
            pasta = raiz / "licencas"
            pasta.mkdir()
            respostas = iter([self.resultado(), self.resultado(1, "nothing to commit"),
                              self.resultado(1, "! [rejected] main -> main (fetch first)")])
            ok, texto = AL.publicar_no_github(pasta, executar=lambda cmd, **kw: next(respostas))
            self.assertFalse(ok)
            self.assertIn("git pull", texto)

            def sem_git(cmd, **kw):
                raise FileNotFoundError
            self.assertIn("não está instalado", AL.publicar_no_github(pasta, executar=sem_git)[1])


class ForaDoInstaladorTests(unittest.TestCase):
    def test_tela_do_administrador_nao_vai_no_executavel(self):
        texto = (APP_DIR / "gerarExe.py").read_text(encoding="utf-8")
        for modulo in ("admin_licencas", "admin_licencas_tela"):
            self.assertIn(f'"--exclude-module", "{modulo}"', texto)
        importa = re.compile(r"^\s*(import|from)\s+admin_licencas", re.M)
        for arq in [*APP_DIR.glob("*.py"), *APP_DIR.glob("nist_intelligence/*.py")]:
            if arq.name.startswith("admin_licencas"):
                continue
            self.assertIsNone(importa.search(arq.read_text(encoding="utf-8")), arq.name)   # o app não importa

    def test_atalho_sem_powershell(self):
        bat = (APP_DIR / "Administrar licencas.bat").read_bytes()
        self.assertIn(b"\r\n", bat)                             # cmd.exe precisa de CRLF
        self.assertIn(b"admin_licencas_tela.py", bat)
        self.assertIn(b"pythonw.exe", bat)                      # sem janela de console


@unittest.skipUnless(TEM_TK and sys.platform == "win32", "tela real só no Windows (CI)")
class TelaRealTests(Base):
    def setUp(self):
        super().setUp()
        import admin_licencas_tela as T
        self.T = T
        adm = self.admin()
        adm.iniciar()
        self.tela = T.TelaAdministrador(pasta=self.pub_dir, admin=adm)
        self.tela.withdraw()
        self.addCleanup(self.tela.destroy)

    def esperar(self, condicao, limite=20):
        fim = time.time() + limite
        while time.time() < fim and not condicao():
            self.tela.update()
            time.sleep(0.02)
        self.assertTrue(condicao())

    def test_colar_emitir_e_ativar(self):
        self.tela.caixa_pedido.insert("1.0", self.pedido())
        self.tela._ler_pedido()
        self.assertEqual(self.tela.pedido["tipo"], "ativacao")
        self.tela.modalidade.set("business")
        self.tela.unidade.set("Loja Centro")
        self.tela.organizacao.set("Empresa Fictícia Ltda")
        with mock.patch.object(self.T.messagebox, "askyesno", return_value=True):
            self.tela.emitir()
        self.esperar(lambda: bool(self.tela.chave))
        self.assertEqual(self.tela.clipboard_get(), self.tela.chave)   # a chave já fica copiada
        lic = L.ativar(self.tela.chave, self.inst_dir, self.pub())
        self.assertEqual((lic["modalidade"], lic["organizacao"]), ("business", "Empresa Fictícia Ltda"))

    def test_credenciar_pela_tela(self):
        inst = L.instalacao(self.inst_dir)
        self.tela.caixa_pedido.insert("1.0", L.pedido_credenciamento("CD" * 20, "SD Fulano", inst))
        self.tela._ler_pedido()
        self.tela.papel.set("revisor")
        with mock.patch.object(self.T.messagebox, "askyesno", return_value=True):
            self.tela.credenciar()
        self.esperar(lambda: not self.tela._ocupado)
        self.assertEqual(L.credenciados(self.pub()).get("CD" * 20, {}).get("papel"), "revisor")


if __name__ == "__main__":
    unittest.main()
