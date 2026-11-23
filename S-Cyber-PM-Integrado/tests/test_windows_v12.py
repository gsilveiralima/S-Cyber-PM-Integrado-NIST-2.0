"""Testes REAIS no Windows (rodam no CI windows-latest; pulados nos outros sistemas):

* assinatura pelo Windows (SignedCms do .NET, formSign.assinar_bytes) com um certificado
  temporário de chave NÃO exportável, conferida pelo verificador em Python;
* pacote de consolidação gerado e importado com essa assinatura;
* coletor avulso (coletor_nist.ps1) executado de verdade e importado pelo painel;
* validade do certificado lida pelo PowerShell para os avisos de abertura.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

APP_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP_DIR))

from nist_intelligence import core, crypto, notificacoes, package, signing  # noqa: E402

WINDOWS = sys.platform == 'win32'


def _ps(script):
    r = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command',
                        script], capture_output=True, text=True, timeout=180)
    if r.returncode or not r.stdout.strip():
        raise RuntimeError(f'PowerShell: {r.stderr or r.stdout or "sem saída"}')
    return r.stdout.strip()


@unittest.skipUnless(WINDOWS, 'somente no Windows')
class AssinaturaWindowsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Os mesmos parâmetros documentados no appSCyberPM.py para o certificado do usuário.
        cls.thumb = _ps("$ErrorActionPreference='Stop'; $c = New-SelfSignedCertificate -Subject 'CN=S-Cyber NIST CI' "
                        "-KeyAlgorithm RSA -KeyLength 2048 -KeyExportPolicy NonExportable "
                        "-CertStoreLocation Cert:\\CurrentUser\\My -NotAfter (Get-Date).AddDays(30); "
                        "$c.Thumbprint").splitlines()[-1].strip()

    @classmethod
    def tearDownClass(cls):
        _ps(f"Remove-Item 'Cert:\\CurrentUser\\My\\{cls.thumb}' -DeleteKey")

    def test_assinatura_do_windows_conferida_em_python(self):
        cms = signing.windows_signer(self.thumb)(b'conteudo real')
        info = signing.verify_detached(b'conteudo real', cms)
        self.assertEqual(info['thumb'], self.thumb.upper())
        self.assertEqual(info['subject'], 'S-Cyber NIST CI')
        self.assertTrue(info['signing_time'])
        with self.assertRaises(signing.SignatureError):
            signing.verify_detached(b'conteudo alterado', cms)

    def test_pacote_assinado_pelo_windows(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            a = core.connect(tmp / 'a.db', crypto.derive_key(os.urandom(32)))
            b = core.connect(tmp / 'b.db', crypto.derive_key(os.urandom(32)))
            try:
                a.actor = b.actor = 'ci'
                core.save_sub_assessment(a, 'GV.PO-01', 3, 4)
                package.build(a, tmp / 'p.scnist', 'Unidade CI', 'Pacote-CI-2026!', signing.windows_signer(self.thumb))
                r = package.import_package(b, tmp / 'p.scnist', 'Pacote-CI-2026!', [self.thumb])
                self.assertTrue(r['trusted'])
                self.assertEqual(core.consolidated_view(b)[1]['unit'], 'Unidade CI')
            finally:
                a.close()
                b.close()

    def test_validade_do_certificado_para_os_avisos(self):
        not_after = notificacoes.certificate_not_after(self.thumb)
        self.assertEqual(len(not_after or ''), 10)
        self.assertIn(notificacoes.cert_days_left(not_after), range(28, 32))


@unittest.skipUnless(WINDOWS, 'somente no Windows')
class ColetorAvulsoWindowsTests(unittest.TestCase):
    def test_coletor_avulso_roda_e_e_importado(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            shutil.copy(APP_DIR / 'coletor_nist.ps1', tmp / 'coletor_nist.ps1')
            subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File',
                            str(tmp / 'coletor_nist.ps1')], capture_output=True, text=True, timeout=240, check=True)
            arquivos = list(tmp.glob('coleta_*.json'))
            self.assertEqual(len(arquivos), 1)
            db = core.connect(tmp / 'n.db', crypto.derive_key(os.urandom(32)))
            try:
                db.actor = 'ci'
                cid = core.import_collection(db, arquivos[0])
                host = core.collections_by_host(db)[0]
                self.assertEqual(host[0], cid)
                self.assertEqual(host[2].upper(), os.environ['COMPUTERNAME'].upper())
                self.assertGreater(sum(host[7].values()), 10)          # verificações avaliadas
            finally:
                db.close()


if __name__ == '__main__':
    unittest.main()
