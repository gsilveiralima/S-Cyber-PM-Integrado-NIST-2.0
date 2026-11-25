"""Tela do administrador (admin_licencas_tela.py): pedidos, emissão sem PowerShell e envio ao GitHub."""
import importlib.util
import re
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.parse
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

    def test_aceita_o_email_inteiro_colado(self):
        """O administrador copia o e-mail todo, com o pedido quebrado em linhas pelo Gmail."""
        pedido = self.pedido()
        _, corpo, _ = L.email_pedido(pedido)
        quebrado = corpo.replace(pedido, "SCPM-PEDIDO-\n" + "\n".join(
            pedido[len("SCPM-PEDIDO-"):][i:i + 60] for i in range(0, len(pedido) - 12, 60)))
        colado = "De: Fulano <fulano@exemplo.com>\r\nPara: suporte\r\n\r\n" + quebrado.replace("\n", "\r\n")
        r = AL.resumo_pedido(colado)
        self.assertEqual(r["tipo"], "ativacao")
        self.assertEqual(r["pedido"], pedido)

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


class EmailTests(Base):
    """Pedido por e-mail com um clique (no lugar do WhatsApp) e resposta pronta do administrador."""

    def test_email_do_pedido_de_ativacao(self):
        pedido = self.pedido()
        assunto, corpo, link = L.email_pedido(pedido)
        inst = L.ler_pedido(pedido)["instalacao"]
        self.assertIn(inst, assunto)
        self.assertIn(pedido, corpo)
        self.assertTrue(link.startswith("mailto:scybersuporte@gmail.com?subject="))
        self.assertLess(len(link), 2000)              # limite prático do mailto: no Windows
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(link).query)
        recebido = q["body"][0]
        self.assertIn("\r\n", recebido)              # quebras de linha de e-mail
        # O administrador cola o corpo inteiro ou só o pedido: ambos são reconhecidos.
        linha = next(x for x in recebido.splitlines() if x.startswith("SCPM-PEDIDO-ATIVACAO."))
        self.assertEqual(AL.resumo_pedido(linha)["dados"]["instalacao"], inst)

    def test_email_do_pedido_de_certificado(self):
        pedido = L.pedido_credenciamento("AB" * 20, "SD Fulano", L.instalacao(self.inst_dir))
        assunto, corpo, _ = L.email_pedido(pedido)
        self.assertIn("SD Fulano", assunto)
        self.assertIn("CREDENCIAMENTO", corpo)

    def test_resposta_pronta_ativa(self):
        adm = self.admin()
        adm.iniciar()
        lic, chave = adm.emitir(self.pedido(), "Loja", modalidade="business")
        resposta = AL.resposta_licenca(lic, chave)
        self.assertIn("S-Cyber Business", resposta)
        linha = next(x for x in resposta.splitlines() if x.startswith("SCPM1."))
        self.assertEqual(L.ativar(linha, self.inst_dir, self.pub())["licenca_id"], lic["licenca_id"])

    def test_endereco_num_lugar_so(self):
        for arq in [*APP_DIR.glob("*.py"), *APP_DIR.glob("nist_intelligence/*.py")]:
            if arq.name != "modLicenca.py":
                self.assertNotIn("scybersuporte@", arq.read_text(encoding="utf-8"), arq.name)


class RepetidoESiteTests(Base):
    def test_ja_credenciado_evita_assinar_de_novo(self):
        adm = self.admin()
        adm.iniciar()
        pedido = L.pedido_credenciamento("EF" * 20, "SD Fulano", L.instalacao(self.inst_dir))
        self.assertFalse(AL.ja_credenciado(adm, pedido, "usuario"))
        adm.credenciar_pedido(pedido, "usuario")
        self.assertTrue(AL.ja_credenciado(adm, "e-mail inteiro\n\n" + pedido + "\n\nComputador: x", "usuario"))
        self.assertFalse(AL.ja_credenciado(adm, pedido, "revisor"))        # outro papel: assina de novo

    def test_pagina_de_envio_do_site(self):
        self.assertEqual(AL.pagina_de_envio(), "https://github.com/gsilveiralima/S-Cyber-PM-Integrado-NIST-2.0"
                                               "/upload/main/S-Cyber-PM-Integrado/licencas")


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
                return self.resultado(0, " M S-Cyber-PM-Integrado/licencas/credenciamentos.scsig"
                                      if cmd[3] == "status" else "")
            ok, _ = AL.publicar_no_github(pasta, "Licenças: teste", executar)
            self.assertTrue(ok)
            self.assertEqual([c[3] for c in feitos], ["status", "add", "commit", "push"])
            self.assertEqual(feitos[1][-1], str(Path("S-Cyber-PM-Integrado") / "licencas"))
            self.assertIn("--", feitos[2])                      # commit só dessa pasta

    def test_nada_novo_nao_e_falha(self):
        """Visto pelo autor: o clone tinha outro arquivo alterado e as listas já estavam no GitHub."""
        with tempfile.TemporaryDirectory() as tmp:
            raiz = Path(tmp)
            (raiz / ".git").mkdir()
            pasta = raiz / "licencas"
            pasta.mkdir()
            feitos = []

            def executar(cmd, **kw):
                feitos.append(cmd[3])
                return self.resultado()                          # status vazio: listas sem mudança
            ok, texto = AL.publicar_no_github(pasta, executar=executar)
            self.assertTrue(ok)
            self.assertIn("Nada novo", texto)
            self.assertEqual(feitos, ["status", "push"])

    def test_nada_novo_e_push_recusado(self):
        with tempfile.TemporaryDirectory() as tmp:
            raiz = Path(tmp)
            (raiz / ".git").mkdir()
            pasta = raiz / "licencas"
            pasta.mkdir()
            respostas = iter([self.resultado(0, " M licencas/x"), self.resultado(),
                              self.resultado(1, "no changes added to commit"),
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
        self.assertNotIn(b"\n", bat.replace(b"\r\n", b""))
        bat.decode("ascii")                                     # sem acentos: o cmd.exe lê em outra codificação
        self.assertIn(b"admin_licencas_tela.py", bat)
        self.assertIn(b"pythonw.exe", bat)                      # sem janela de console
        # Pasta nova (clone): cria o ambiente sozinho, com as versões travadas.
        self.assertIn(b"py -3 -m venv .venv", bat)
        self.assertIn(b"-r requirements-lock.txt", bat)
        # Visto pelo autor: com pythonw, um erro na abertura sumia em silêncio. O atalho confere
        # antes, com o python.exe (com console), e mostra o motivo.
        self.assertIn(b'python.exe" -c "import admin_licencas_tela"', bat)
        self.assertLess(bat.index(b"import admin_licencas_tela"), bat.index(b"pythonw.exe"))


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
        copiado = self.tela.clipboard_get()                            # a resposta pronta já fica copiada
        self.assertIn("Como ativar", copiado)
        self.assertIn("\n" + self.tela.chave + "\n", copiado)
        lic = L.ativar(self.tela.chave, self.inst_dir, self.pub())
        self.assertEqual((lic["modalidade"], lic["organizacao"]), ("business", "Empresa Fictícia Ltda"))

    def test_erro_nao_some_em_silencio(self):
        with tempfile.TemporaryDirectory() as tmp:
            arq = Path(tmp) / "erro.log"
            with mock.patch.object(self.T, "ARQUIVO_ERRO", arq), \
                    mock.patch.object(self.T.messagebox, "showerror") as mostrou:
                self.T._registrar_erro("Falhou.", "Traceback: detalhe do erro")
            mostrou.assert_called_once()
            self.assertIn("detalhe do erro", arq.read_text(encoding="utf-8"))

    def test_credenciar_pela_tela(self):
        inst = L.instalacao(self.inst_dir)
        self.tela.caixa_pedido.insert("1.0", L.pedido_credenciamento("CD" * 20, "SD Fulano", inst))
        self.tela._ler_pedido()
        self.tela.papel.set("revisor")
        with mock.patch.object(self.T.messagebox, "askyesno", return_value=True):
            self.tela.credenciar()
        self.esperar(lambda: not self.tela._ocupado)
        self.assertEqual(L.credenciados(self.pub()).get("CD" * 20, {}).get("papel"), "revisor")
        # De novo, com o mesmo papel: não assina outra vez; oferece o envio (pelo site, pasta sem Git).
        antes = (self.pub_dir / "credenciamentos.scsig").read_bytes()
        with mock.patch.object(self.T.messagebox, "askyesno", return_value=True), \
                mock.patch.object(self.tela, "enviar_pelo_site") as site:
            self.tela.credenciar()
        site.assert_called_once()
        self.assertEqual((self.pub_dir / "credenciamentos.scsig").read_bytes(), antes)


if __name__ == "__main__":
    unittest.main()
