"""26/11/2026, computador corporativo: o único certificado da conta era da organização (CN=<GUID>,
chave não RSA). Foi enviado no pedido e credenciado por engano; o S-Cyber não consegue usá-lo."""
import sys
import unittest
from datetime import datetime
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
sys.path.insert(0, str(BASE / "tests"))

import admin_licencas  # noqa: E402
import modDiagnostico as D  # noqa: E402
import modLicenca as L  # noqa: E402
from test_ativacao import COMUM, Base  # noqa: E402

AGORA = datetime(2026, 11, 26, 14, 0)
ORG = {"thumb": "00507D3A4F8D9659EB931A11FBEDCBBB005A3173", "titular": "CN=4e18402a-61b9-42d2-a051-8bb4d82dd08a",
       "chave_privada": True, "inicio": "2026-10-29T00:00:00", "fim": "2027-10-29T00:00:00", "algoritmo": "ECC"}
MEU = {"thumb": "A" * 40, "titular": "CN=Fulano", "chave_privada": True, "inicio": "2026-11-26T00:00:00",
       "fim": "2027-11-26T00:00:00", "algoritmo": "RSA"}


class ClassificacaoTests(unittest.TestCase):
    def test_nao_rsa_nao_serve_nem_credenciado(self):
        self.assertEqual(D.classificar(ORG, [], AGORA, [ORG["thumb"]]), "nao_rsa")
        self.assertIn("NÃO SERVE", D.SITUACAO["nao_rsa"])

    def test_so_o_da_organizacao_manda_criar_o_certificado(self):
        geral, _ = D.resumo_certificados([ORG], [], [ORG["thumb"]], AGORA)
        self.assertEqual(geral, "nao_rsa")
        self.assertIn("Criar meu certificado", D.PROXIMA_ACAO[geral])

    def test_o_certificado_novo_resolve(self):
        self.assertEqual(D.resumo_certificados([ORG, MEU], [], [MEU["thumb"]], AGORA)[0], "pronto")
        self.assertEqual(D.resumo_certificados([ORG, MEU], [], [], AGORA)[0], "nao_autorizado")

    def test_titular_codigo_parece_da_organizacao(self):
        self.assertTrue(D.parece_da_organizacao(ORG["titular"]))
        self.assertTrue(D.parece_da_organizacao("4e18402a-61b9-42d2-a051-8bb4d82dd08a"))
        self.assertFalse(D.parece_da_organizacao("CN=SGT Gabriel Silveira Lima"))


class AdministradorTests(Base):
    def test_administrador_recusa_chave_que_nao_e_rsa(self):
        adm = self.admin()
        adm.iniciar()
        pedido = L.pedido_credenciamento(COMUM[0], ORG["titular"], L.instalacao(self.inst_dir), algoritmo="ECC")
        self.assertIn("NÃO serve", admin_licencas.resumo_pedido(pedido)["texto"])
        with self.assertRaises(L.ErroLicenca):
            adm.credenciar_pedido(pedido)

    def test_aviso_para_titular_codigo_em_pedido_antigo(self):
        pedido = L.pedido_credenciamento(COMUM[0], ORG["titular"], L.instalacao(self.inst_dir))   # sem algoritmo
        self.assertIn("parece um certificado do Windows", admin_licencas.resumo_pedido(pedido)["texto"])

    def test_pedido_normal_sem_aviso(self):
        pedido = L.pedido_credenciamento(COMUM[0], "Fulano de Tal", L.instalacao(self.inst_dir), algoritmo="RSA")
        self.assertNotIn("ATENÇÃO", admin_licencas.resumo_pedido(pedido)["texto"])
        adm = self.admin()
        adm.iniciar()
        adm.credenciar_pedido(pedido)


if __name__ == "__main__":
    unittest.main()
