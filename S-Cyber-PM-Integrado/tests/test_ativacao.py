"""Ativação (licenças), credenciamento, administradores, diagnóstico e migração de perfil."""
import datetime as dt
import json
import os
import re
import sys
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path
from unittest import mock

APP_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP_DIR))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.hazmat.primitives.serialization import pkcs7  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

import admin_licencas  # noqa: E402
import modDiagnostico  # noqa: E402
import modLicenca as L  # noqa: E402
import modPerfil  # noqa: E402
from nist_intelligence import core, signing  # noqa: E402


def _cert(cn):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    c = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
         .not_valid_after(now + dt.timedelta(days=365)).sign(key, hashes.SHA256()))

    def assinar(dados):
        return (pkcs7.PKCS7SignatureBuilder().set_data(dados).add_signer(c, key, hashes.SHA256())
                .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.DetachedSignature]))
    return signing.thumbprint(c), assinar


GABRIEL = _cert("SGT Gabriel (teste)")
MAJOR = _cert("MAJ Leonidio (teste)")
COMUM = _cert("Policial comum")
ADMINS_TESTE = {GABRIEL[0]: "SGT Gabriel", MAJOR[0]: "MAJ Leonídio"}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.pub_dir = self.dir / "licencas"
        self.inst_dir = self.dir / "inst"
        self.p = mock.patch.dict(L.ADMINISTRADORES_FIXOS, ADMINS_TESTE, clear=True)
        self.p.start()
        self.hoje = date.today()

    def tearDown(self):
        self.p.stop()
        self.tmp.cleanup()

    def admin(self, quem=GABRIEL):
        return admin_licencas.Admin(self.pub_dir, assinador=quem[1], thumb=quem[0], hoje=self.hoje)

    def pub(self, baixar=None):
        return L.Publicacao(pasta_cache=self.dir / "cache", pasta_pacote=self.pub_dir,
                            baixar=baixar or (lambda nome: (_ for _ in ()).throw(OSError("sem rede"))))

    def pedido(self, pasta=None):
        return L.pedido_ativacao(L.instalacao(pasta or self.inst_dir), "1.6")


class LicencaTests(Base):
    def test_emitir_ativar_e_conferir(self):
        adm = self.admin()
        adm.iniciar()
        lic, chave = adm.emitir(self.pedido(), "1º BPM", dias=365)
        self.assertTrue(chave.startswith("SCPM1."))
        ativada = L.ativar(chave, self.inst_dir, self.pub())
        self.assertEqual(ativada["licenca_id"], lic["licenca_id"])
        ok, lic2, erro = L.estado(self.inst_dir, self.pub())
        self.assertTrue(ok, erro)
        self.assertEqual(lic2["_assinada_por"], "SGT Gabriel")

    def test_outra_instalacao_expirada_revogada_e_lista_vencida(self):
        adm = self.admin()
        adm.iniciar()
        _, chave = adm.emitir(self.pedido(), "1º BPM", dias=10)
        with self.assertRaises(L.ErroLicenca) as c:
            L.ativar(chave, self.dir / "outra", self.pub())
        self.assertEqual(c.exception.codigo, "outra_instalacao")
        L.ativar(chave, self.inst_dir, self.pub())
        ok, _, erro = L.estado(self.inst_dir, self.pub(), hoje=self.hoje + timedelta(days=11))
        self.assertEqual(erro.codigo, "expirada")
        ok, _, erro = L.estado(self.inst_dir, self.pub(), hoje=self.hoje + timedelta(days=9))
        self.assertTrue(ok)
        # lista de revogações vencida (sem republicação em 30 dias): bloqueia
        _, chave = adm.emitir(self.pedido(), "1º BPM", dias=365)
        L.ativar(chave, self.inst_dir, self.pub())
        ok, _, erro = L.estado(self.inst_dir, self.pub(), hoje=self.hoje + timedelta(days=L.VALIDADE_LISTA_DIAS + 1))
        self.assertEqual(erro.codigo, "lista_vencida")
        # revogação
        lic = L.estado(self.inst_dir, self.pub())[1]
        self.admin(MAJOR).revogar(lic["licenca_id"], "teste")
        ok, _, erro = L.estado(self.inst_dir, self.pub())
        self.assertEqual(erro.codigo, "revogada")

    def test_sem_lista_bloqueia_e_chave_invalida(self):
        adm = self.admin()
        _, chave = adm.emitir(self.pedido(), "1º BPM")          # sem iniciar: não há revogações publicadas
        with self.assertRaises(L.ErroLicenca) as c:
            L.ativar(chave, self.inst_dir, self.pub())
        self.assertEqual(c.exception.codigo, "sem_lista")
        adm.iniciar()
        estragada = chave[:-12] + ("A" if chave[-12] != "A" else "B") + chave[-11:]
        with self.assertRaises(L.ErroLicenca) as c:
            L.ativar(estragada, self.inst_dir, self.pub())
        self.assertIn(c.exception.codigo, ("invalida",))
        with self.assertRaises(L.ErroLicenca):
            L.ativar("qualquer coisa", self.inst_dir, self.pub())

    def test_usuario_comum_nao_emite(self):
        with self.assertRaises(L.ErroLicenca) as c:
            admin_licencas.Admin(self.pub_dir, assinador=COMUM[1], thumb=COMUM[0])
        self.assertEqual(c.exception.codigo, "nao_admin")
        # mesmo forjando o documento, o aplicativo recusa a assinatura de quem não é admin
        self.admin().iniciar()
        inst = L.instalacao(self.inst_dir)
        falsa = {"tipo": "licenca", "licenca_id": "LIC-X", "instalacao": inst["id"], "maquina": inst["maquina"],
                 "valida_ate": "2099-01-01"}
        with self.assertRaises(L.ErroLicenca) as c:
            L.ativar(L.para_chave(L.empacotar(falsa, COMUM[1])), self.inst_dir, self.pub())
        self.assertEqual(c.exception.codigo, "nao_admin")

    def test_renovar_e_transferir(self):
        adm = self.admin()
        adm.iniciar()
        lic, chave = adm.emitir(self.pedido(), "1º BPM", dias=5)
        nova, chave2 = adm.renovar(chave, dias=400)
        self.assertEqual(nova["substitui"], lic["licenca_id"])
        L.ativar(chave2, self.inst_dir, self.pub())
        outra = self.dir / "maquina2"
        trans, chave3 = self.admin(MAJOR).transferir(chave2, self.pedido(outra))
        self.assertEqual(trans["instalacao"], L.instalacao(outra)["id"])
        self.assertEqual(L.estado(self.inst_dir, self.pub())[2].codigo, "revogada")    # a antiga deixa de valer
        L.ativar(chave3, outra, self.pub())
        linhas = admin_licencas.verificar(self.pub_dir)
        self.assertFalse([x for x in linhas if x.startswith("ERRO")], linhas)
        ops = [json.loads(L.abrir(x, ADMINS_TESTE)[0]["operacao"] and "1") for x in
               (self.pub_dir / "registro.jsonl").read_bytes().splitlines()]
        self.assertGreaterEqual(len(ops), 5)

    def test_modalidade_business_assinada_e_mantida(self):
        """S-Cyber 2.0: a modalidade vem da licença ASSINADA; renovar e transferir a mantêm."""
        adm = self.admin()
        adm.iniciar()
        lic, chave = adm.emitir(self.pedido(), "Empresa Fictícia", dias=30, modalidade="business")
        self.assertEqual(lic["modalidade"], "business")
        ativada = L.ativar(chave, self.inst_dir, self.pub())
        self.assertEqual(L.nome_produto(ativada), "S-Cyber Business")
        self.assertFalse(L.recurso_liberado(ativada, "sei"))               # integração da PM fica fora
        self.assertTrue(L.recurso_liberado(ativada, "diagnostico"))
        nova, _ = adm.renovar(chave, dias=60)
        self.assertEqual(nova["modalidade"], "business")
        self.assertEqual(L.modalidade({}), "pm")                          # licença antiga, sem o campo
        self.assertTrue(L.recurso_liberado({}, "sei"))
        with self.assertRaises(L.ErroLicenca):
            adm.emitir(self.pedido(), "x", modalidade="gratis")

    def test_registro_adulterado_e_detectado(self):
        adm = self.admin()
        adm.iniciar()
        adm.emitir(self.pedido(), "1º BPM")
        reg = self.pub_dir / "registro.jsonl"
        linhas = reg.read_bytes().splitlines()
        doc = json.loads(linhas[-1])
        conteudo = json.loads(__import__("base64").b64decode(doc["conteudo"]))
        conteudo["administrador"] = "Outro"
        doc["conteudo"] = __import__("base64").b64encode(json.dumps(conteudo).encode()).decode()
        linhas[-1] = json.dumps(doc).encode()
        reg.write_bytes(b"\n".join(linhas) + b"\n")
        self.assertTrue(any(x.startswith("ERRO registro") for x in admin_licencas.verificar(self.pub_dir)))


class PublicacaoTests(Base):
    def test_usa_a_maior_sequencia_e_guarda_em_cache(self):
        adm = self.admin()
        adm.iniciar()
        antiga = (self.pub_dir / "revogacoes.scsig").read_bytes()
        adm.revogar("LIC-1", "x")
        nova = (self.pub_dir / "revogacoes.scsig").read_bytes()
        (self.pub_dir / "revogacoes.scsig").write_bytes(antiga)      # cópia do instalador desatualizada
        pub = self.pub(baixar=lambda nome: nova if nome == "revogacoes" else (self.pub_dir / f"{nome}.scsig").read_bytes())
        doc = pub.vigente("revogacoes")
        self.assertEqual([r["licenca_id"] for r in doc["revogadas"]], ["LIC-1"])
        self.assertEqual(pub.origem["revogacoes"], "online")
        self.assertTrue((self.dir / "cache" / "revogacoes.scsig").exists())
        # sem rede: a cache (mais nova) vence a cópia do pacote; uma versão antiga online não volta atrás
        pub2 = self.pub(baixar=lambda nome: antiga)
        self.assertEqual(len(pub2.vigente("revogacoes")["revogadas"]), 1)

    def test_credenciamento_e_papeis(self):
        adm = self.admin()
        adm.iniciar()
        t, _ = COMUM
        pedido = L.pedido_credenciamento(t, "Policial", L.instalacao(self.inst_dir))
        adm.credenciar_pedido(pedido, "revisor")
        self.assertEqual(L.credenciados(self.pub()), {t: {"titular": "Policial", "papel": "revisor"}})
        self.assertEqual(L.papel(t, self.pub()), "revisor")
        self.assertEqual(L.papel(GABRIEL[0], self.pub()), "administrador")
        adm.descredenciar(t, "saiu da unidade")
        self.assertEqual(L.credenciados(self.pub()), {})
        with self.assertRaises(L.ErroLicenca):
            adm.credenciar("XYZ")

    def test_recuperacao_de_administrador(self):
        self.admin().iniciar()
        novo = _cert("SGT Gabriel (certificado novo)")
        # Gabriel perdeu o certificado: o Major autoriza o novo
        self.admin(MAJOR).administradores(adicionar=novo[0], nome="SGT Gabriel (novo)", remover=GABRIEL[0])
        with mock.patch.dict(L.ADMINISTRADORES_FIXOS, ADMINS_TESTE, clear=True):
            adm_novo = admin_licencas.Admin(self.pub_dir, assinador=novo[1], thumb=novo[0], hoje=self.hoje)
            self.assertEqual(adm_novo.nome, "SGT Gabriel (novo)")
            with self.assertRaises(L.ErroLicenca):
                admin_licencas.Admin(self.pub_dir, assinador=GABRIEL[1], thumb=GABRIEL[0])
            with self.assertRaises(L.ErroLicenca):
                adm_novo.administradores(remover=novo[0])


class DiagnosticoTests(unittest.TestCase):
    def _c(self, thumb, chave=True, dias=100):
        agora = dt.datetime.now()
        return {"thumb": thumb, "titular": "CN=x", "chave_privada": chave, "algoritmo": "RSA",
                "inicio": (agora - dt.timedelta(days=1)).isoformat(timespec="seconds"),
                "fim": (agora + dt.timedelta(days=dias)).isoformat(timespec="seconds")}

    def test_classificacao(self):
        a, b = "A" * 40, "B" * 40
        self.assertEqual(modDiagnostico.resumo_certificados([], [a])[0], "ausente")
        self.assertEqual(modDiagnostico.resumo_certificados([self._c(b)], [a])[0], "nao_autorizado")
        self.assertEqual(modDiagnostico.resumo_certificados([self._c(a, chave=False)], [a])[0], "sem_chave")
        self.assertEqual(modDiagnostico.resumo_certificados([self._c(a, dias=-2)], [a])[0], "vencido")
        self.assertEqual(modDiagnostico.resumo_certificados([self._c(b)], [a], credenciados={b: {}})[0], "pronto")

    def test_duas_copias_e_relatorio(self):
        with tempfile.TemporaryDirectory() as tmp:
            prog1, prog2 = Path(tmp) / "copia1" / "app.py", Path(tmp) / "copia2" / "app.py"
            for p in (prog1, prog2):
                p.parent.mkdir()
                p.write_text("")
            self.assertIsNone(modDiagnostico.registrar_execucao(prog1, "1.6", tmp))
            self.assertIn("copia1", modDiagnostico.registrar_execucao(prog2, "1.6", tmp))
            with mock.patch.dict(os.environ, {"APPDATA": tmp, "LOCALAPPDATA": tmp}):
                texto = modDiagnostico.relatorio("1.6", prog2, ["A" * 40], "certificado", "falhou",
                                                 publicacao=L.Publicacao(pasta_cache=Path(tmp) / "c",
                                                                         pasta_pacote=Path(tmp) / "p", online=False),
                                                 certificados=[self._c("B" * 40)])
        for trecho in ("Versão em execução : 1.6", "ETAPA QUE FALHOU   : Certificado digital", "NÃO ATIVA",
                       "NAO_AUTORIZADO", "PRÓXIMA AÇÃO", "pedido de credenciamento"):
            self.assertIn(trecho, texto)

    def test_sem_ativacao_a_proxima_acao_e_ativar(self):
        # Validação no Windows (24/11/2026): "NÃO ATIVA" aparecia junto de "Nenhuma falha informada".
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"APPDATA": tmp, "LOCALAPPDATA": tmp}):
                texto = modDiagnostico.relatorio("1.6", Path(tmp) / "app.py", ["A" * 40],
                                                 publicacao=L.Publicacao(pasta_cache=Path(tmp) / "c",
                                                                         pasta_pacote=Path(tmp) / "p", online=False),
                                                 certificados=[self._c("A" * 40)], analisar_perfil=False)
        self.assertIn("NÃO ATIVA", texto)
        self.assertNotIn("Nenhuma falha", texto)
        self.assertIn("Ative esta instalação", texto.split("PRÓXIMA AÇÃO:")[1])

    def test_nome_do_certificado_sem_injecao(self):
        self.assertEqual(modDiagnostico.nome_certificado('SGT Fulano, O=Hack"'), "S-Cyber PM - SGT Fulano OHack")
        with self.assertRaises(ValueError):
            modDiagnostico.nome_certificado(",,,")


class PerfilTests(unittest.TestCase):
    """Troca de certificado: A (antigo, acessível) -> B (novo)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.pasta = Path(self.tmp.name)
        self.ka, self.kb = os.urandom(32), os.urandom(32)
        self.ta, self.tb = "A" * 40, "B" * 40
        self.chaves = {self.ta: self.ka, self.tb: self.kb}
        modPerfil.gravar_opcoes(self.pasta / "scyber_pm.opcoes", self.ka, self.ta,
                                {"usuario": "agente", "senha_acesso": {"h": "x"}, "trocar_senha": False})
        db = core.connect(self.pasta / "nist" / "nist.db", modPerfil.chave_nist(self.ka))
        db.actor = "SGT Teste"
        core.save_risk(db, "Senha exposta do servidor", "Contas", 3, 3, "PR")
        iid = core.save_incident(db, "Phishing", "Detecção", "nota sigilosa", "Alta", True, "02/03/2026")
        eid = core.save_evidence(db, "log.txt", "a" * 64, "", 10, "Log", incident_id=iid)
        core.link_evidence(db, "GV.PO-01", eid)
        db.close()
        agora = dt.datetime.now()
        self.certs = [{"thumb": t, "chave_privada": True, "titular": f"CN={t[0]}", "algoritmo": "RSA",
                       "inicio": (agora - dt.timedelta(days=1)).isoformat(), "fim": (agora + dt.timedelta(days=9)).isoformat()}
                      for t in (self.ta, self.tb)]

    def tearDown(self):
        self.tmp.cleanup()

    def derivar(self, thumb):
        return self.chaves[thumb]

    def test_magico_igual_ao_formopcoes(self):
        fonte = (APP_DIR / "formOpcoes.py").read_text(encoding="utf-8")
        self.assertTrue(f'MAGICO = b"{modPerfil.MAGICO_OPCOES.decode()}"' in fonte, "MAGICO diferente")

    def test_inventario_e_migracao_completa(self):
        inv, _ = modPerfil.analisar(self.tb, self.certs, self.pasta, self.derivar)
        self.assertEqual({a["situacao"] for a in inv}, {"outro_certificado"})
        rel = modPerfil.migrar(self.ta, self.ka, self.tb, self.kb, self.pasta, actor="SGT Teste")
        self.assertEqual(rel["restauracao"], "restauração de teste conferida")
        self.assertGreater(rel["nist"]["registros"]["risks"], 0)
        # os ativos abrem com B; os originais ficam guardados e ainda abrem com A
        self.assertEqual(modPerfil.ler_opcoes(self.pasta / "scyber_pm.opcoes", self.kb, self.tb)["usuario"],
                         "agente")
        db = core.connect(self.pasta / "nist" / "nist.db", modPerfil.chave_nist(self.kb))
        try:
            self.assertEqual(core.risks(db)[0]["title"], "Senha exposta do servidor")
            self.assertEqual(core.incidents(db)[0]["notes"], "nota sigilosa")
            self.assertEqual(core.evidence_counts(db), {"GV.PO-01": 1})
            for t in core._CHAINS:
                self.assertTrue(core.verify_chain(db, t)[0], t)
            self.assertEqual(core.audit_list(db)[0][3:5], ("Perfil", "Migrar certificado"))
        finally:
            db.close()
        arquivo = Path(rel["arquivo"])
        self.assertTrue((arquivo / "LEIA-ME.txt").exists())
        self.assertEqual(core.key_status(arquivo / "nist.db", modPerfil.chave_nist(self.ka)), "abre")
        self.assertTrue((arquivo / "relatorio_migracao.json").exists())
        inv, _ = modPerfil.analisar(self.tb, self.certs, self.pasta, self.derivar)
        ativos = [a for a in inv if a["caminho"].endswith(("nist.db", "scyber_pm.opcoes")) and "arquivo" not in a["caminho"]]
        self.assertEqual({a["situacao"] for a in ativos}, {"atual"})

    def test_recupera_copia_antiga_quando_o_ativo_e_novo(self):
        nist = self.pasta / "nist"
        (nist / "nist.db").rename(nist / "nist.db.antigo")
        modPerfil.gravar_opcoes(self.pasta / "scyber_pm.opcoes", self.kb, self.tb, {"usuario": "agente"})
        core.connect(nist / "nist.db", modPerfil.chave_nist(self.kb)).close()     # banco novo, vazio
        rel = modPerfil.migrar(self.ta, self.ka, self.tb, self.kb, self.pasta, origem_nist=nist / "nist.db.antigo")
        self.assertIsNone(rel["opcoes"])                    # as opções já eram do certificado atual
        self.assertFalse((nist / "nist.db.antigo").exists())
        db = core.connect(nist / "nist.db", modPerfil.chave_nist(self.kb))
        self.assertEqual(len(core.risks(db)), 1)
        db.close()
        self.assertEqual(len(list(Path(rel["arquivo"]).glob("nist.db*"))), 2)   # vazio e antigo guardados

    def test_sem_chave_antiga_preserva_e_so_cria_perfil_com_confirmacao(self):
        certs = [self.certs[1]]
        inv, _ = modPerfil.analisar(self.tb, certs, self.pasta, self.derivar)
        self.assertEqual({a["situacao"] for a in inv}, {"sem_chave"})
        with self.assertRaises(PermissionError):
            core.rekey(self.pasta / "nist" / "nist.db", self.kb, self.kb, self.pasta / "x.db")
        with self.assertRaises(modPerfil.ErroPerfil):
            modPerfil.novo_perfil("sim", self.pasta)
        self.assertTrue((self.pasta / "nist" / "nist.db").exists())
        arquivo = modPerfil.novo_perfil("novo perfil", self.pasta)
        self.assertFalse((self.pasta / "nist" / "nist.db").exists())
        self.assertTrue((arquivo / "nist.db").exists() and (arquivo / "scyber_pm.opcoes").exists())

    def test_relatorio_mostra_quem_abre_cada_arquivo(self):
        with mock.patch.dict(os.environ, {"APPDATA": str(self.pasta.parent), "LOCALAPPDATA": str(self.pasta)}):
            with mock.patch.object(modPerfil, "pasta_dados", lambda: self.pasta):
                texto = modDiagnostico.relatorio("1.6", "app.py", [self.tb], "opcoes", "outra chave", self.tb,
                                                 publicacao=L.Publicacao(pasta_cache=self.pasta / "c",
                                                                         pasta_pacote=self.pasta / "p", online=False),
                                                 certificados=self.certs, derivar=self.derivar)
        self.assertIn("abre com OUTRO certificado acessível (AAAAAAAA…)", texto)
        self.assertIn("ASSISTENTE DE PERFIL", texto)


class AberturaIntegradaTests(unittest.TestCase):
    def test_abertura_ativacao_certificado_e_perfil_ligados(self):
        app = (APP_DIR / "appSCyberPM.py").read_text(encoding="utf-8")
        ordem = [app.index(x) for x in ("modLicenca.estado(publicacao=publicacao)",
                                        "validar_certificado(modLicenca.credenciados(publicacao))",
                                        "formOpcoes.iniciar(_thumbprint_normalizado())")]
        self.assertEqual(ordem, sorted(ordem))
        self.assertIn("FormAbertura(self.parent, etapa", app)
        self.assertNotIn("SCYBER_SEM_LICENCA", app)          # sem atalho para pular a ativação
        self.assertTrue(re.search(r'if "--diagnostico" in sys.argv\[1:\]', app))
        self.assertIn("FormPerfil(self.root", (APP_DIR / "modNist.py").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()


class PublicacaoDoRepositorioTests(unittest.TestCase):
    """O que está em licencas/ precisa ter sido assinado por um administrador de verdade."""

    def test_assinaturas_publicadas(self):
        pasta = APP_DIR / "licencas"
        pub = L.Publicacao(pasta_cache=Path(tempfile.gettempdir()) / "scyber_sem_cache", pasta_pacote=pasta,
                           online=False)
        for arq in pasta.glob("*.scsig"):
            self.assertIsNotNone(pub.documento(arq.stem), f"{arq.name} sem assinatura de administrador válida")
        reg = pasta / "registro.jsonl"
        if reg.exists():
            for linha in filter(None, reg.read_bytes().splitlines()):
                L.abrir(linha, pub.administradores())

    def test_ferramenta_admin_fora_do_executavel(self):
        texto = (APP_DIR / "gerarExe.py").read_text(encoding="utf-8")
        self.assertIn('"--exclude-module", "admin_licencas"', texto)
        self.assertNotIn("admin_licencas", (APP_DIR / "appSCyberPM.py").read_text(encoding="utf-8"))
