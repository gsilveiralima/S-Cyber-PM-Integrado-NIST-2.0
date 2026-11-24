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


if __name__ == "__main__":
    unittest.main()
