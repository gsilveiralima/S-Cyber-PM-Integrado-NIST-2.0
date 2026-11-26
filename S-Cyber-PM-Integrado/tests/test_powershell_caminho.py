"""26/11/2026, computador corporativo: 'PowerShell não encontrado' — a PATH não tinha a pasta do
PowerShell. O S-Cyber passa a usar o caminho completo e explica bloqueios da organização."""
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))

import modDiagnostico  # noqa: E402
import modPowerShell  # noqa: E402

PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"


class _Saida:
    def __init__(self, stdout=b"", stderr=b"", returncode=0):
        self.stdout, self.stderr, self.returncode = stdout, stderr, returncode


class CaminhoCompletoTests(unittest.TestCase):
    def _executavel(self, existentes, which=None):
        with mock.patch.object(sys, "platform", "win32"), \
                mock.patch.dict(os.environ, {"SystemRoot": r"C:\Windows"}), \
                mock.patch.object(os.path, "isfile", side_effect=lambda c: c in existentes), \
                mock.patch.object(modPowerShell.shutil, "which", return_value=which):
            return modPowerShell.executavel()

    def test_usa_o_caminho_do_windows_sem_depender_da_path(self):
        self.assertEqual(self._executavel({os.path.join(r"C:\Windows", "System32", "WindowsPowerShell", "v1.0",
                                                        "powershell.exe")}),
                         os.path.join(r"C:\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe"))

    def test_programa_de_32_bits_usa_sysnative(self):
        sysnative = os.path.join(r"C:\Windows", "Sysnative", "WindowsPowerShell", "v1.0", "powershell.exe")
        self.assertEqual(self._executavel({sysnative}), sysnative)

    def test_sem_a_pasta_padrao_procura_na_path(self):
        self.assertEqual(self._executavel(set(), which=r"D:\ps\powershell.exe"), r"D:\ps\powershell.exe")
        self.assertEqual(self._executavel(set(), which=None), "powershell")

    def test_a_linha_de_comando_usa_o_executavel(self):
        with mock.patch.object(modPowerShell, "executavel", return_value=PS):
            self.assertEqual(modPowerShell.argumentos("x")[:2], [PS, "-NoProfile"])
            self.assertEqual(modPowerShell.argumentos("x", codificado=True)[0], PS)


@mock.patch.dict(os.environ, {"SCYBER_POWERSHELL_FORA_DO_WINDOWS": "1"})
class MensagensTests(unittest.TestCase):
    def _falha(self, exc):
        with mock.patch.object(subprocess, "run", side_effect=exc):
            with self.assertRaises(modPowerShell.ErroPowerShell) as erro:
                modPowerShell.executar("x")
        return str(erro.exception)

    def test_nao_encontrado_explica_o_que_fazer(self):
        texto = self._falha(FileNotFoundError())
        self.assertIn("não foi encontrado", texto)
        self.assertIn("TI", texto)

    def test_bloqueado_pela_politica(self):
        self.assertIn("bloqueou", self._falha(PermissionError()))
        erro = OSError("bloqueado")
        erro.winerror = 1260                       # ERROR_ACCESS_DISABLED_BY_POLICY
        self.assertIn("bloqueou", self._falha(erro))

    def test_modo_restrito_do_powershell(self):
        saida = _Saida(b"", "Cannot invoke method. Method invocation is supported only on core types in this "
                            "language mode.".encode(), returncode=1)
        with mock.patch.object(subprocess, "run", return_value=saida):
            with self.assertRaisesRegex(modPowerShell.ErroPowerShell, "modo restrito"):
                modPowerShell.executar("x")


class DiagnosticoTests(unittest.TestCase):
    def test_falha_ao_listar_nao_vira_falta_de_certificado(self):
        with mock.patch.object(modDiagnostico, "listar_certificados",
                               side_effect=modPowerShell.ErroPowerShell("O Windows PowerShell não foi encontrado")):
            texto = modDiagnostico.relatorio("2.0.4", "SCyberPM.exe", [], "certificado", "Certificado digital",
                                             analisar_perfil=False)
        self.assertIn("NÃO quer dizer que falte certificado", texto)
        self.assertNotIn("Nenhum certificado nesta conta", texto)


if __name__ == "__main__":
    unittest.main()
