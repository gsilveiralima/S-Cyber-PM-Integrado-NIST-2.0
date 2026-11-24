"""S-Cyber 2.0, Fase 3: adaptador único de PowerShell (M4), caminhos (M5) e código removido (M9)."""
import ast
import importlib.util
import base64
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))

import modPowerShell  # noqa: E402


class _Saida:
    def __init__(self, stdout=b"", stderr=b"", returncode=0):
        self.stdout, self.stderr, self.returncode = stdout, stderr, returncode


@mock.patch.dict(os.environ, {"SCYBER_POWERSHELL_FORA_DO_WINDOWS": "1", "PSModulePath": r"C:\ps7"})
class PowerShellTests(unittest.TestCase):
    def test_argumentos_ambiente_e_utf8(self):
        with mock.patch.object(subprocess, "run", return_value=_Saida("\ufeffAção ok\nOK fim\n".encode())) as run:
            r = modPowerShell.executar("Write-Output 1", variaveis={"SCYBER_X": "valor"}, timeout=7)
        args, kw = run.call_args
        self.assertEqual(args[0][:5], ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass"])
        self.assertIn("UTF8Encoding", args[0][-1])
        self.assertTrue(args[0][-1].endswith("Write-Output 1"))
        self.assertEqual(kw["timeout"], 7)
        self.assertEqual(kw["env"]["SCYBER_X"], "valor")
        self.assertNotIn("PSModulePath", kw["env"])
        self.assertEqual(r.linhas, ["Ação ok", "OK fim"])     # acentos e BOM corretos
        self.assertEqual(r.ultima_linha, "OK fim")

    def test_codificado_e_entrada(self):
        with mock.patch.object(subprocess, "run", return_value=_Saida(b'{"a": 1}\n')) as run:
            r = modPowerShell.executar("$x = 'aspas \"duplas\"'", entrada="QUJD", codificado=True)
        args, kw = run.call_args
        self.assertEqual(args[0][-2], "-EncodedCommand")
        self.assertTrue(base64.b64decode(args[0][-1]).decode("utf-16-le").endswith("$x = 'aspas \"duplas\"'"))
        self.assertEqual(kw["input"], b"QUJD")
        self.assertEqual(r.json(), {"a": 1})

    def test_falhas_viram_erro_em_portugues(self):
        with mock.patch.object(subprocess, "run", side_effect=FileNotFoundError()):
            with self.assertRaisesRegex(modPowerShell.ErroPowerShell, "não encontrado"):
                modPowerShell.executar("x")
        with mock.patch.object(subprocess, "run", side_effect=subprocess.TimeoutExpired("powershell", 3)):
            with self.assertRaisesRegex(modPowerShell.ErroPowerShell, "Tempo esgotado"):
                modPowerShell.executar("x", timeout=3)
        with mock.patch.object(subprocess, "run", return_value=_Saida(b"", "falhou".encode())):
            r = modPowerShell.executar("x")
            self.assertEqual(r.ultima_linha, "falhou")
            with self.assertRaisesRegex(modPowerShell.ErroPowerShell, "falhou"):
                r.json()

    def test_fora_do_windows_nao_executa(self):
        with mock.patch.dict(os.environ, {"SCYBER_POWERSHELL_FORA_DO_WINDOWS": "0"}), \
                mock.patch.object(sys, "platform", "linux"), \
                mock.patch.object(subprocess, "run") as run:
            with self.assertRaises(modPowerShell.ErroPowerShell):
                modPowerShell.executar("x")
            run.assert_not_called()

    @unittest.skipUnless(importlib.util.find_spec("tkinter"), "exige tkinter (roda no Windows)")
    def test_tela_de_usuarios_passa_a_ter_tempo_limite(self):
        import formGerenciadorUsuarios as g
        with mock.patch.object(subprocess, "run", return_value=_Saida(b"ok\n")) as run:
            self.assertEqual(g.executar_ps("Get-LocalUser"), "ok")
        self.assertEqual(run.call_args[1]["timeout"], modPowerShell.TIMEOUT_PADRAO)
        with mock.patch.object(subprocess, "run", return_value=_Saida(b"", b"negado", 1)):
            with self.assertRaisesRegex(RuntimeError, "negado"):
                g.executar_ps("x")


class UmSoExecutorTests(unittest.TestCase):
    """Ninguém além do modPowerShell monta a linha de comando do PowerShell.
    Exceção registrada: os processos paralelos da Corujinha (Popen com encerramento
    próprio), que serão revistos na Fase 4 junto com a transparência da Corujinha (S7)."""
    PERMITIDOS = {"modPowerShell.py", "formCoruja.py"}

    def test_sem_execucao_avulsa(self):
        avulsos = []
        for arq in list(BASE.glob("*.py")) + list((BASE / "nist_intelligence").glob("*.py")):
            if arq.name in self.PERMITIDOS:
                continue
            for no in ast.walk(ast.parse(arq.read_text(encoding="utf-8"))):
                if isinstance(no, ast.List) and no.elts and isinstance(no.elts[0], ast.Constant) \
                        and str(no.elts[0].value).lower() in ("powershell", "powershell.exe"):
                    avulsos.append(f"{arq.name}:{no.lineno}")
        self.assertEqual(avulsos, [])


class RemovidosTests(unittest.TestCase):
    def test_codigo_morto_e_musica_removidos(self):
        for nome in ("formSplashScreen.py", "Surveillance Pulse.mp3", "modSom.py"):
            self.assertFalse((BASE / nome).exists(), nome)
        self.assertNotIn("mp3", (BASE / "gerarExe.py").read_text(encoding="utf-8"))
        self.assertNotIn("modSom", (BASE / "formCoruja.py").read_text(encoding="utf-8"))


class CaminhosTests(unittest.TestCase):
    def setUp(self):
        import modCaminhos
        self.m = modCaminhos
        self.addCleanup(modCaminhos.definir_organizacao, None)

    def test_mesmas_pastas_de_antes_no_windows(self):
        with mock.patch.dict(os.environ, {"APPDATA": r"C:/U/AppData/Roaming", "LOCALAPPDATA": r"C:/U/AppData/Local"}):
            self.assertEqual(self.m.pasta_dados(criar=False), Path(r"C:/U/AppData/Roaming") / "SCyberPM")
            self.assertEqual(self.m.pasta_nist(), Path(r"C:/U/AppData/Roaming") / "SCyberPM" / "nist")
            self.assertEqual(self.m.pasta_instalacao(), Path(r"C:/U/AppData/Local") / "SCyberPM")
            import modLicenca
            import modPerfil
            self.assertEqual(modPerfil.pasta_dados(), self.m.pasta_dados(criar=False))
            self.assertEqual(modLicenca.pasta_instalacao(), self.m.pasta_instalacao())

    def test_organizacao_isola_os_dados_mas_nao_a_instalacao(self):
        with mock.patch.dict(os.environ, {"APPDATA": "/a", "LOCALAPPDATA": "/l"}):
            self.assertEqual(self.m.definir_organizacao("Empresa X/../Y"), "Empresa_X_.._Y")
            self.assertEqual(self.m.pasta_dados(criar=False), Path("/a/SCyberPM/perfis/Empresa_X_.._Y"))
            self.assertEqual(self.m.pasta_instalacao(), Path("/l/SCyberPM"))
            for invalido in ("..", "", "  ", "/"):
                self.assertIsNone(self.m.definir_organizacao(invalido))
            self.assertEqual(self.m.pasta_dados(criar=False), Path("/a/SCyberPM"))

    def test_uma_so_definicao(self):
        """Nenhum módulo além do modCaminhos monta a pasta SCyberPM a partir do APPDATA/LOCALAPPDATA."""
        avulsos = []
        for arq in list(BASE.glob("*.py")) + list((BASE / "nist_intelligence").glob("*.py")):
            if arq.name == "modCaminhos.py":
                continue
            for no in ast.walk(ast.parse(arq.read_text(encoding="utf-8"))):
                if isinstance(no, ast.Call) and isinstance(no.func, ast.Attribute) and no.func.attr == "get" \
                        and no.args and isinstance(no.args[0], ast.Constant) \
                        and no.args[0].value in ("APPDATA", "LOCALAPPDATA"):
                    avulsos.append(f"{arq.name}:{no.lineno}")
        self.assertEqual(avulsos, [])


class _JanelaFalsa:
    """Imita o after/winfo_exists do Tk rodando os agendamentos num laço simples."""
    def __init__(self):
        self.fila, self.viva, self.cursor = [], True, None

    def after(self, _ms, funcao, *args):
        self.fila.append((funcao, args))

    def winfo_exists(self):
        return self.viva

    def configure(self, **kw):
        self.cursor = kw.get("cursor", self.cursor)

    def rodar(self, limite=5.0):
        import time
        fim = time.time() + limite
        while self.fila and time.time() < fim:
            funcao, args = self.fila.pop(0)
            funcao(*args)
            time.sleep(0.01)


class SegundoPlanoTests(unittest.TestCase):
    def test_entrega_resultado_e_erro_na_thread_da_tela(self):
        import threading
        from modRecursos import em_segundo_plano
        janela, recebidos = _JanelaFalsa(), []
        principal = threading.get_ident()
        em_segundo_plano(janela, lambda: threading.get_ident(),
                         lambda r, e: recebidos.append((r != principal, e, threading.get_ident() == principal)))
        em_segundo_plano(janela, lambda: 1 / 0, lambda r, e: recebidos.append((r, type(e).__name__, True)))
        janela.rodar()
        self.assertIn((True, None, True), recebidos)          # trabalho fora, entrega dentro
        self.assertIn((None, "ZeroDivisionError", True), recebidos)

    def test_janela_fechada_nao_recebe(self):
        from modRecursos import em_segundo_plano
        janela, recebidos = _JanelaFalsa(), []
        janela.viva = False
        em_segundo_plano(janela, lambda: 1, lambda r, e: recebidos.append(r))
        janela.rodar(0.5)
        self.assertEqual(recebidos, [])

    @unittest.skipUnless(importlib.util.find_spec("tkinter"), "exige tkinter (roda no Windows)")
    def test_senha_vazada_em_segundo_plano(self):
        import modSenhaVazada
        from nist_intelligence import fontes
        janela, gravou, terminou = _JanelaFalsa(), [], []
        respostas = {"boa": (fontes.SEM_CORRESPONDENCIA, 0), "vazada": (fontes.CORRESPONDENCIA, 9)}
        with mock.patch.object(modSenhaVazada, "messagebox") as mb:
            modSenhaVazada.conferir_e_continuar(janela, [("boa", "a"), ("vazada", "b")], lambda: gravou.append(1),
                                                consultar=lambda s: respostas[s],
                                                ao_terminar=lambda: terminou.append(1))
            janela.rodar()
            self.assertEqual(gravou, [])                          # a vazada bloqueia a gravação
            mb.showwarning.assert_called_once()
            modSenhaVazada.conferir_e_continuar(janela, [("boa", "a"), ("", "vazia")], lambda: gravou.append(1),
                                                consultar=lambda s: respostas[s])
            janela.rodar()
        self.assertEqual((gravou, terminou, janela.cursor), ([1], [1], ""))


class SemTravarTests(unittest.TestCase):
    """As chamadas demoradas apontadas na auditoria (M8) não rodam mais na thread da tela."""

    def test_pontos_corrigidos(self):
        fonte = {n: (BASE / n).read_text(encoding="utf-8") for n in
                 ("formListCerts.py", "formGerenciadorUsuarios.py", "formOpcoes.py", "formLogin.py",
                  "formAbertura.py")}
        self.assertIn("em_segundo_plano(self, trabalho, pronto)", fonte["formListCerts.py"])
        self.assertIn("em_segundo_plano(self, lambda: excluir_certificado(", fonte["formListCerts.py"])
        self.assertIn("em_segundo_plano(self, lambda: (listar_usuarios(), listar_grupos())",
                      fonte["formGerenciadorUsuarios.py"])
        self.assertIn("em_segundo_plano(self, lambda: func(*args), pronto)", fonte["formGerenciadorUsuarios.py"])
        self.assertIn("em_segundo_plano(self, modHello.disponivel", fonte["formOpcoes.py"])
        self.assertIn('em_segundo_plano(self, lambda: modHello.verificar("Cadastrar', fonte["formOpcoes.py"])
        self.assertIn("em_segundo_plano(self, lambda: modHello.disponivel()[0]", fonte["formLogin.py"])
        self.assertNotIn("_hello_disponivel()", fonte["formLogin.py"])
        # Senhas digitadas em janelas protegidas contra captura (como o login)
        self.assertIn('pedir_senha(self, "Recuperação"', fonte["formAbertura.py"])
        self.assertIn('pedir_senha(self, "Senha do arquivo"', fonte["formListCerts.py"])
        self.assertNotIn("simpledialog.askstring(\"Recupera", fonte["formAbertura.py"])


if __name__ == "__main__":
    unittest.main()
