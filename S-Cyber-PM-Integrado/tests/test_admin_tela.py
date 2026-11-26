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


class AdministradoresTests(Base):
    def test_texto_de_exemplo_nao_vira_administrador(self):
        """Visto em 25/11: o exemplo NOVA_IMPRESSAO foi executado e entrou na lista."""
        adm = self.admin()
        adm.iniciar()
        for ruim in ("NOVA_IMPRESSAO", "THUMB", "AB" * 19, "G" * 40, "<IMPRESSAO DIGITAL DE 40 CARACTERES>"):
            with self.assertRaises(L.ErroLicenca, msg=ruim):
                adm.administradores(adicionar=ruim, nome="x")
        boa = " ".join(["ab12"] * 10)                                   # com espaços, minúsculas
        adm.administradores(adicionar=boa, nome="Novo")
        self.assertIn("AB12" * 10, L.Publicacao(pasta_cache=self.dir / "c", pasta_pacote=self.pub_dir,
                                                online=False).administradores())

    def test_remover_entrada_invalida_ja_publicada(self):
        adm = self.admin()
        adm.iniciar()
        doc = adm._lista("administradores")
        doc["administradores"]["NOVA_IMPRESSAO"] = "lixo"
        adm._publicar("administradores", doc)
        adm.administradores(remover="NOVA_IMPRESSAO")
        admins = L.Publicacao(pasta_cache=self.dir / "c2", pasta_pacote=self.pub_dir, online=False).administradores()
        self.assertNotIn("NOVA_IMPRESSAO", admins)


def clone_falso(raiz, url=f"https://github.com/{L.REPOSITORIO}.git"):
    """Imita um clone do repositório do S-Cyber: .git com o 'origin' e a pasta das listas."""
    (raiz / ".git").mkdir()
    (raiz / ".git" / "config").write_text(f'[core]\n\tbare = false\n[remote "origin"]\n\turl = {url}\n'
                                          '\tfetch = +refs/heads/*:refs/remotes/origin/*\n', encoding="utf-8")
    pasta = raiz / "S-Cyber-PM-Integrado" / "licencas"
    pasta.mkdir(parents=True)
    return pasta


class GithubTests(unittest.TestCase):
    def test_sincronizar_antes_de_operar(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(AL.sincronizar(Path(tmp) / "licencas"), (True, ""))          # ZIP: nada a fazer
            pasta = clone_falso(Path(tmp))
            feitos = []

            def executar(cmd, **kw):
                feitos.append(cmd[3:])
                return subprocess.CompletedProcess([], 0, "Fast-forward", "")
            ok, texto = AL.sincronizar(pasta, executar)
            self.assertTrue(ok)
            self.assertEqual(feitos, [["pull", "--ff-only", "--autostash"]])
            ok, texto = AL.sincronizar(pasta,
                                       lambda c, **k: subprocess.CompletedProcess([], 1, "", "fatal: diverging"))
            self.assertFalse(ok)
            self.assertIn("git pull", texto)

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
            pasta = clone_falso(raiz)
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

    def test_merge_pela_metade_explica_o_conserto(self):
        """Visto pelo autor: 'cannot do a partial commit during a merge'."""
        with tempfile.TemporaryDirectory() as tmp:
            raiz = Path(tmp)
            pasta = clone_falso(raiz)
            (raiz / ".git" / "MERGE_HEAD").write_text("abc", encoding="utf-8")
            chamadas = []
            ok, texto = AL.publicar_no_github(pasta, executar=lambda *a, **k: chamadas.append(a))
            self.assertFalse(ok)
            self.assertIn("git merge --abort", texto)
            self.assertIn("git reset --hard origin/main", texto)
            self.assertEqual(chamadas, [])                       # nem tenta o git
            ok, texto = AL.sincronizar(pasta, executar=lambda *a, **k: chamadas.append(a))
            self.assertFalse(ok)
            self.assertEqual(chamadas, [])
            (raiz / ".git" / "MERGE_HEAD").unlink()
            (raiz / ".git" / "rebase-merge").mkdir()
            self.assertIn("rebase", AL.publicar_no_github(pasta, executar=lambda *a, **k: None)[1])

    def test_nada_novo_nao_e_falha(self):
        """Visto pelo autor: o clone tinha outro arquivo alterado e as listas já estavam no GitHub."""
        with tempfile.TemporaryDirectory() as tmp:
            raiz = Path(tmp)
            pasta = clone_falso(raiz)
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
            pasta = clone_falso(raiz)
            # Visto pelo autor: outra pasta de administração enviou antes. Junta e reenvia sozinho.
            respostas = iter([self.resultado(0, " M licencas/x"), self.resultado(),
                              self.resultado(1, "no changes added to commit"),
                              self.resultado(1, "! [rejected] main -> main (fetch first)"),
                              self.resultado(0, "Successfully rebased"), self.resultado(0, "main -> main")])
            feitos = []

            def executar(cmd, **kw):
                feitos.append(" ".join(cmd[3:5]))
                return next(respostas)
            ok, texto = AL.publicar_no_github(pasta, executar=executar)
            self.assertTrue(ok, texto)
            self.assertIn("juntei", texto)
            self.assertEqual(feitos[-2:], ["pull --rebase", "push"])
            # A MESMA lista mudou dos dois lados: desfaz e explica como refazer.
            respostas = iter([self.resultado(0, " M licencas/x"), self.resultado(), self.resultado(),
                              self.resultado(1, "! [rejected] main -> main (fetch first)"),
                              self.resultado(1, "CONFLICT (content): Merge conflict in credenciamentos.scsig"),
                              self.resultado()])
            feitos.clear()
            ok, texto = AL.publicar_no_github(pasta, executar=executar)
            self.assertFalse(ok)
            self.assertIn("reset --hard origin/main", texto)
            self.assertEqual(feitos[-1], "rebase --abort")

            def sem_git(cmd, **kw):
                raise FileNotFoundError
            self.assertIn("não está instalado", AL.publicar_no_github(pasta, executar=sem_git)[1])


class RepositorioCertoTests(unittest.TestCase):
    """Revisão de 26/11/2026: achar um .git subindo as pastas não basta."""

    def test_aceita_o_clone_do_s_cyber_em_qualquer_forma_de_url(self):
        for url in (f"https://github.com/{L.REPOSITORIO}.git", f"https://github.com/{L.REPOSITORIO}",
                    f"git@github.com:{L.REPOSITORIO}.git", f"https://GitHub.com/{L.REPOSITORIO.upper()}/"):
            with tempfile.TemporaryDirectory() as tmp:
                pasta = clone_falso(Path(tmp), url)
                self.assertEqual(AL.raiz_git(pasta), Path(tmp).resolve(), url)

    def test_pasta_de_zip_dentro_de_outro_repositorio(self):
        with tempfile.TemporaryDirectory() as tmp:
            outro = Path(tmp)
            clone_falso(outro, "https://github.com/alguem/outro-projeto.git")
            pasta = outro / "Downloads" / "S-Cyber-main" / "S-Cyber-PM-Integrado" / "licencas"
            pasta.mkdir(parents=True)
            raiz, motivo = AL.situacao_git(pasta)
            self.assertIsNone(raiz)
            self.assertIn("outro repositório", motivo)
            chamadas = []
            ok, texto = AL.publicar_no_github(pasta, executar=lambda *a, **k: chamadas.append(a))
            self.assertFalse(ok)
            self.assertEqual(chamadas, [])                       # nenhum git no repositório errado
            self.assertEqual(AL.sincronizar(pasta, executar=lambda *a, **k: chamadas.append(a)), (True, ""))
            self.assertEqual(chamadas, [])

    def test_clone_de_outro_repositorio_no_mesmo_caminho(self):
        with tempfile.TemporaryDirectory() as tmp:
            pasta = clone_falso(Path(tmp), "https://github.com/alguem/S-Cyber-copia.git")
            raiz, motivo = AL.situacao_git(pasta)
            self.assertIsNone(raiz)
            self.assertIn(L.REPOSITORIO, motivo)

    def test_worktree_com_arquivo_git(self):
        with tempfile.TemporaryDirectory() as tmp:
            principal = Path(tmp) / "principal"
            principal.mkdir()
            clone_falso(principal)
            (principal / ".git" / "worktrees" / "wt").mkdir(parents=True)
            (principal / ".git" / "worktrees" / "wt" / "commondir").write_text("../..", encoding="utf-8")
            wt = Path(tmp) / "wt"
            (wt / "S-Cyber-PM-Integrado" / "licencas").mkdir(parents=True)
            (wt / ".git").write_text(f"gitdir: {principal / '.git' / 'worktrees' / 'wt'}", encoding="utf-8")
            self.assertEqual(AL.raiz_git(wt / "S-Cyber-PM-Integrado" / "licencas"), wt.resolve())


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
