"""Revisão de segurança de 26/11/2026: validade da lista de administradores, anti-retorno de listas
e validade do certificado do administrador na data da assinatura."""
import datetime as dt
import json
import shutil
import sys
from datetime import timedelta
from pathlib import Path
from unittest import mock

APP_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP_DIR))
sys.path.insert(0, str(APP_DIR / "tests"))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.hazmat.primitives.serialization import pkcs7  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

import admin_licencas  # noqa: E402
import modLicenca as L  # noqa: E402
from nist_intelligence import signing  # noqa: E402
from test_ativacao import COMUM, GABRIEL, Base  # noqa: E402

ADMINS_REAIS = dict(L.ADMINISTRADORES_FIXOS)      # antes de os testes trocarem pelos de teste


def _cert_com_validade(cn, inicio_dias, fim_dias):
    """Certificado com validade relativa a hoje (ex.: -400, -10 = venceu há 10 dias)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nome = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    agora = dt.datetime.now(dt.timezone.utc)
    c = (x509.CertificateBuilder().subject_name(nome).issuer_name(nome).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(agora + dt.timedelta(days=inicio_dias))
         .not_valid_after(agora + dt.timedelta(days=fim_dias)).sign(key, hashes.SHA256()))

    def assinar(dados):
        return (pkcs7.PKCS7SignatureBuilder().set_data(dados).add_signer(c, key, hashes.SHA256())
                .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.DetachedSignature]))
    return signing.thumbprint(c), assinar


class ListaDeAdministradoresTests(Base):
    def _novo_admin_com_lista(self):
        adm = self.admin()
        adm.iniciar()
        adm.administradores(adicionar=COMUM[0], nome="Admin temporário")
        return adm

    def test_lista_vigente_autoriza_o_admin_adicionado(self):
        self._novo_admin_com_lista()
        self.assertIn(COMUM[0], self.pub().administradores())

    def test_lista_de_administradores_vencida_nao_autoriza_ninguem_a_mais(self):
        """Achado Alto: uma cópia antiga ainda assinada continuava autorizando quem foi removido."""
        self.hoje = dt.date.today() - timedelta(days=40)         # lista emitida há 40 dias: venceu há 10
        self._novo_admin_com_lista()
        pub = self.pub()
        admins = pub.administradores()
        self.assertNotIn(COMUM[0], admins)
        self.assertEqual(set(admins), set(L.ADMINISTRADORES_FIXOS))
        self.assertIn("vencida", pub.recusadas["administradores"])

    def test_copia_antiga_nao_volta_depois_de_vista_a_nova(self):
        """Anti-retorno: depois de aceitar a sequência N, uma cópia N-1 (ainda válida) é recusada."""
        adm = self._novo_admin_com_lista()                        # sequência 2: com o admin temporário
        antiga = (self.pub_dir / "administradores.scsig").read_bytes()
        adm.administradores(remover=COMUM[0])                     # sequência 3: removido
        self.assertNotIn(COMUM[0], self.pub().administradores())  # este computador viu a 3
        vistas = json.loads((self.dir / "cache" / L.SEQUENCIAS_VISTAS).read_text("utf-8"))
        self.assertEqual(vistas["administradores"], 3)
        (self.pub_dir / "administradores.scsig").write_bytes(antiga)   # alguém repõe a cópia antiga
        pub = self.pub()
        self.assertNotIn(COMUM[0], pub.administradores())
        self.assertIn("antiga", pub.recusadas["administradores"])

    def test_anti_retorno_vale_para_revogacoes(self):
        adm = self.admin()
        adm.iniciar()
        lic, _chave = adm.emitir(self.pedido(), "1º BPM", dias=365)
        antes = (self.pub_dir / "revogacoes.scsig").read_bytes()
        adm.revogar(lic["licenca_id"], "teste")
        self.assertIn(lic["licenca_id"], {r["licenca_id"] for r in self.pub().vigente("revogacoes")["revogadas"]})
        (self.pub_dir / "revogacoes.scsig").write_bytes(antes)   # sem a revogação
        # A cópia antiga não pode "desrevogar" a licença: sem a lista atual, o programa para e explica.
        with self.assertRaises(L.ErroLicenca) as erro:
            self.pub().vigente("revogacoes")
        self.assertIn("cópia antiga recusada", str(erro.exception))

    def test_ferramenta_do_administrador_nao_grava_nada_na_pasta_das_listas(self):
        adm = self.admin()
        adm.iniciar()
        adm.administradores(adicionar=COMUM[0], nome="X")
        admin_licencas.verificar(self.pub_dir)
        self.assertFalse((self.pub_dir / "_nao_usado").exists())


class ValidadeDoCertificadoTests(Base):
    def _abrir(self, quem, conteudo):
        bruto = L.empacotar(conteudo, quem[1])
        return L.abrir(bruto, {quem[0]: "Admin"})

    def test_certificado_vencido_nao_assina_mais(self):
        """Achado Médio: a data de expiração era devolvida mas não usada."""
        vencido = _cert_com_validade("Admin vencido", -400, -10)
        with self.assertRaises(L.ErroLicenca) as erro:
            self._abrir(vencido, {"tipo": "licenca", "valida_ate": "2027-01-01"})
        self.assertEqual(erro.exception.codigo, "certificado_vencido")

    def test_certificado_ainda_nao_valido(self):
        futuro = _cert_com_validade("Admin futuro", 5, 400)
        with self.assertRaises(L.ErroLicenca) as erro:
            self._abrir(futuro, {"tipo": "licenca"})
        self.assertEqual(erro.exception.codigo, "certificado_vencido")

    def test_certificado_valido_na_assinatura_e_aceito(self):
        quase = _cert_com_validade("Admin perto de vencer", -360, 1)
        conteudo, info = self._abrir(quase, {"tipo": "licenca",
                                             "valida_ate": (dt.date.today() + timedelta(days=365)).isoformat()})
        self.assertEqual(conteudo["tipo"], "licenca")
        self.assertIn("not_before", info)

    def test_validade_alem_do_prazo_contado_da_assinatura(self):
        hoje = dt.date.today()
        for tipo, prazo in (("credenciamentos", L.VALIDADE_LISTA_DIAS + 1), ("licenca", L.PRAZO_MAX_LICENCA_DIAS)):
            self._abrir(GABRIEL, {"tipo": tipo, "valida_ate": (hoje + timedelta(days=prazo - 1)).isoformat()})
            with self.assertRaises(L.ErroLicenca, msg=tipo):
                self._abrir(GABRIEL, {"tipo": tipo, "valida_ate": (hoje + timedelta(days=prazo + 2)).isoformat()})

    def test_administrador_nao_emite_licenca_longa_demais(self):
        adm = self.admin()
        adm.iniciar()
        with self.assertRaises(L.ErroLicenca):
            adm.emitir(self.pedido(), "1º BPM", dias=L.PRAZO_MAX_LICENCA_DIAS + 1)

    def test_listas_publicadas_no_repositorio_continuam_validas(self):
        """As listas reais publicadas (assinadas por um administrador fixo) passam na política nova."""
        pasta = self.dir / "reais"
        shutil.copytree(APP_DIR / "licencas", pasta)
        with mock.patch.dict(L.ADMINISTRADORES_FIXOS, ADMINS_REAIS, clear=True):
            pub = L.Publicacao(pasta_cache=self.dir / "c", pasta_pacote=pasta, online=False)
            for nome in L.LISTAS:
                self.assertIsNotNone(pub.documento(nome), nome)


class NovoAdministradorPeloPedidoTests(Base):
    def test_adicionar_administrador_a_partir_do_pedido_do_certificado(self):
        """Sem digitar os 40 caracteres: o pedido de credenciamento (ou o e-mail inteiro) basta."""
        adm = self.admin()
        adm.iniciar()
        pedido = L.pedido_credenciamento(COMUM[0], "CAP Novo Administrador", L.instalacao(self.inst_dir))
        email = f"Olá, equipe.\n\nPedido (gerado pelo programa, não altere):\n{pedido[:50]}\n{pedido[50:]}\n\nComputador: X"
        thumb, nome = admin_licencas.thumb_do_pedido(email)
        self.assertEqual((thumb, nome), (COMUM[0], "CAP Novo Administrador"))
        self.assertEqual(admin_licencas.thumb_do_pedido(pedido, "MAJ Fulano")[1], "MAJ Fulano")
        adm.administradores(thumb, nome)
        self.assertEqual(self.pub().administradores()[COMUM[0]], "CAP Novo Administrador")
        with self.assertRaises(L.ErroLicenca):          # pedido de ATIVAÇÃO não serve
            admin_licencas.thumb_do_pedido(self.pedido())
