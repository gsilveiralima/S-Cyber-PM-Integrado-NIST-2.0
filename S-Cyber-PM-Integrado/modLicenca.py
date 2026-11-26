"""Ativação da instalação, credenciamento de certificados e lista de administradores.

Três assuntos SEPARADOS:
  * ATIVAÇÃO — a instalação só abre com uma licença emitida para ela (id da instalação
    + impressão da máquina), assinada por um administrador;
  * AUTENTICAÇÃO — cada policial entra com o próprio certificado (chave privada no
    Windows) e a senha; o certificado precisa estar credenciado (lista assinada) ou na
    lista fixa do appSCyberPM.py, ou ter sido emitido pela AC institucional;
  * DADOS — a chave que cifra opções e banco vem do certificado (modPerfil).

Autoridade: só os ADMINISTRADORES (SGT Gabriel Silveira Lima e MAJ Leonídio) emitem,
renovam, transferem e revogam. Todo documento é assinado no Windows deles (CMS/SHA-256,
chave não exportável) e conferido aqui com nist_intelligence.signing; o certificado de
quem assinou precisa estar na lista de administradores. Nenhum segredo de emissão vai
no instalador: só as impressões digitais dos administradores.

Publicação: licencas/ no repositório do GitHub (revogações, credenciamentos,
administradores e o registro das operações). O aplicativo busca on-line a cada abertura;
sem rede, usa a última cópia conferida até a validade da lista (30 dias). Assim, uma
revogação vale na próxima abertura com internet e, no máximo, em 30 dias sem ela.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import socket
import sys
import urllib.error
import urllib.request
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from nist_intelligence import signing

# Administradores fixados no aplicativo (impressão digital -> nome). Uma lista nova de
# administradores só vale se assinada por um administrador já reconhecido.
ADMINISTRADORES_FIXOS = {
    "ECD4B39DE69C171732449C0D8378F312661482DA": "MAJ Leonídio Alves de Moraes Junior",
    "B330B18E7E10C2F4F9182E911516A13DA0591CC9": "SGT Gabriel Silveira Lima",
    "7CB36ED157A30DCEA274B44450B78C16370F15EE": "SGT Gabriel Silveira Lima",
}
REPOSITORIO = "gsilveiralima/S-Cyber-PM-Integrado-NIST-2.0"
# Para onde vão os pedidos de ativação e de credenciamento (botão "Enviar pedido por e-mail").
EMAIL_SUPORTE = "scybersuporte@gmail.com"
URL_PUBLICACAO = f"https://raw.githubusercontent.com/{REPOSITORIO}/main/S-Cyber-PM-Integrado/licencas/"
LISTAS = ("administradores", "revogacoes", "credenciamentos")
VALIDADE_LISTA_DIAS = 30          # prazo máximo até uma revogação valer sem internet
PRAZO_MAX_LICENCA_DIAS = 1100     # licença: no máximo ~3 anos a partir da data da assinatura
SEQUENCIAS_VISTAS = "sequencias_vistas.json"   # maior sequência já aceita de cada lista (anti-retorno)
AVISO_LISTA_DIAS = 10             # a partir daqui, avisar que as listas precisam ser republicadas
FORMATO = "scyber-assinado"
PREFIXO_CHAVE = "SCPM1."
PAPEIS = ("usuario", "revisor")
# S-Cyber 2.0: um produto, duas modalidades, definidas na licença ASSINADA (o usuário não troca).
# Licenças antigas, sem o campo, continuam como "pm" (comportamento de antes).
MODALIDADES = {"pm": "S-Cyber PM", "business": "S-Cyber Business"}
EXCLUSIVO_PM = ("sei",)          # integrações institucionais que a modalidade Business não carrega


def modalidade(licenca):
    m = (licenca or {}).get("modalidade", "pm")
    return m if m in MODALIDADES else "pm"


def nome_produto(licenca):
    return MODALIDADES[modalidade(licenca)]


def recurso_liberado(licenca, recurso):
    return not (recurso in EXCLUSIVO_PM and modalidade(licenca) != "pm")


def organizacao(licenca):
    """Organização cujos dados ficam isolados (modalidade Business), ou None (S-Cyber PM: pasta
    padrão, como sempre foi). Vem da licença ASSINADA: o usuário não escolhe nem troca."""
    if modalidade(licenca) != "business":
        return None
    nome = str((licenca or {}).get("organizacao") or (licenca or {}).get("unidade") or "").strip()
    return nome or "empresa"


def organizacao_da_instalacao(pasta=None, publicacao=None):
    """Organização da licença gravada NESTA instalação, mesmo vencida ou revogada: a recuperação
    de dados sem licença precisa achar a pasta certa. Confere a assinatura e a instalação, mas
    não a validade. Sem licença legível: None (pasta padrão)."""
    try:
        inst = instalacao(pasta)
        publicacao = publicacao or Publicacao(pasta_cache=Path(pasta or pasta_instalacao()) / "licencas",
                                              online=False)
        lic, _ = abrir(de_chave(arquivo_licenca(pasta).read_text(encoding="utf-8")), publicacao.administradores())
    except (OSError, ErroLicenca, ValueError, KeyError):
        return None
    if lic.get("tipo") != "licenca" or lic.get("instalacao") != inst["id"]:
        return None
    return organizacao(lic)


class ErroLicenca(Exception):
    def __init__(self, codigo, mensagem):
        super().__init__(mensagem)
        self.codigo = codigo


# ------------------------------------------------------------------ documentos assinados
def _b64(b):
    return base64.b64encode(b).decode("ascii")


def empacotar(conteudo: dict, assinador) -> bytes:
    """assinador(bytes) -> CMS DER (formSign.assinar_bytes com o certificado do admin)."""
    dados = json.dumps(conteudo, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return json.dumps({"formato": FORMATO, "conteudo": _b64(dados), "assinatura": _b64(assinador(dados))},
                      sort_keys=True).encode("utf-8")


def abrir(bruto: bytes, administradores: dict):
    """Confere a assinatura e se quem assinou é administrador. Devolve (conteúdo, info)."""
    try:
        doc = json.loads(bruto)
        if doc.get("formato") != FORMATO:
            raise ValueError
        dados = base64.b64decode(doc["conteudo"])
        cms = base64.b64decode(doc["assinatura"])
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise ErroLicenca("invalida", "Documento em formato desconhecido.") from exc
    try:
        info = signing.verify_detached(dados, cms)
    except signing.SignatureError as exc:
        raise ErroLicenca("invalida", f"Assinatura inválida: {exc}") from exc
    if info["thumb"] not in administradores:
        raise ErroLicenca("nao_admin", f"Assinado por {info['subject']} ({info['thumb'][:8]}…), que não é "
                                       "administrador do S-Cyber PM.")
    info["administrador"] = administradores[info["thumb"]]
    conteudo = json.loads(dados)
    _conferir_data_da_assinatura(info, conteudo)
    return conteudo, info


def _conferir_data_da_assinatura(info, conteudo):
    """Política de validade do certificado do administrador (revisão de 26/11/2026).

    1. O documento precisa dizer quando foi assinado (signingTime do CMS), e essa data precisa
       estar dentro da validade do certificado que assinou: certificado vencido não assina mais.
    2. A validade do documento não pode passar do prazo máximo contado da data da assinatura
       (listas: VALIDADE_LISTA_DIAS; licenças: PRAZO_MAX_LICENCA_DIAS). Assim, mesmo quem tiver a
       chave de um certificado já vencido e "voltar a data" da assinatura só consegue documentos
       que vencem logo depois do fim da validade do certificado.
    Licenças já emitidas continuam valendo depois que o certificado do administrador vence:
    o que conta é a validade na data em que foram assinadas."""
    quando = info.get("signing_time") or ""
    if not quando:
        raise ErroLicenca("invalida", "A assinatura não informa a data em que foi feita; peça um documento novo "
                                      "ao administrador.")
    try:
        dia = datetime.fromisoformat(quando).astimezone(timezone.utc).date()
    except ValueError as exc:
        raise ErroLicenca("invalida", "Data da assinatura ilegível.") from exc
    inicio, fim = info.get("not_before", ""), info.get("not_after", "")
    if not (inicio <= dia.isoformat() <= fim):
        raise ErroLicenca("certificado_vencido",
                          f"Assinado em {dia:%d/%m/%Y}, fora da validade do certificado do administrador "
                          f"({inicio} a {fim}). Peça um documento novo, assinado com um certificado válido.")
    ate = conteudo.get("valida_ate")
    if ate:
        prazo = VALIDADE_LISTA_DIAS + 1 if conteudo.get("tipo") in LISTAS else PRAZO_MAX_LICENCA_DIAS
        if ate > (dia + timedelta(days=prazo)).isoformat():
            raise ErroLicenca("invalida", f"A validade do documento ({ate}) passa do prazo permitido para a data "
                                          f"em que foi assinado ({dia:%d/%m/%Y}).")


# ------------------------------------------------------------------ instalação
def pasta_instalacao():
    import modCaminhos                  # fonte única das pastas (S-Cyber 2.0, M5)
    return modCaminhos.pasta_instalacao()


def maquina():
    """Impressão da máquina: SHA-256 do MachineGuid do Windows (não é segredo, só vínculo)."""
    valor = ""
    if sys.platform == "win32":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0,
                                winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)) as k:
                valor = winreg.QueryValueEx(k, "MachineGuid")[0]
        except OSError:
            valor = ""
    else:
        for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            try:
                valor = Path(p).read_text().strip()
                break
            except OSError:
                pass
    valor = valor or socket.gethostname()
    return hashlib.sha256(("scyber-pm-maquina:" + valor).encode("utf-8")).hexdigest()[:32]


def instalacao(pasta=None):
    """{'id', 'maquina', 'criada_em'} — criado na primeira abertura."""
    pasta = Path(pasta or pasta_instalacao())
    arq = pasta / "instalacao.json"
    try:
        dados = json.loads(arq.read_text(encoding="utf-8"))
        if dados.get("id"):
            return dados
    except (OSError, ValueError):
        pass
    pasta.mkdir(parents=True, exist_ok=True)
    dados = {"id": "INST-" + secrets.token_hex(6).upper(), "maquina": maquina(),
             "criada_em": datetime.now().isoformat(timespec="seconds")}
    arq.write_text(json.dumps(dados, indent=2), encoding="utf-8")
    return dados


def pedido_ativacao(inst, versao=""):
    """Texto que o usuário envia ao administrador (não é segredo)."""
    dados = {"instalacao": inst["id"], "maquina": inst["maquina"], "computador": socket.gethostname(),
             "conta": os.environ.get("USERNAME") or os.environ.get("USER") or "", "versao": versao}
    return "SCPM-PEDIDO-ATIVACAO." + base64.urlsafe_b64encode(json.dumps(dados).encode()).decode().rstrip("=")


def pedido_credenciamento(thumb, titular, inst):
    dados = {"thumbprint": thumb, "titular": titular, "instalacao": inst["id"],
             "computador": socket.gethostname(), "conta": os.environ.get("USERNAME") or ""}
    return "SCPM-PEDIDO-CERTIFICADO." + base64.urlsafe_b64encode(json.dumps(dados).encode()).decode().rstrip("=")


def email_pedido(pedido, para=EMAIL_SUPORTE):
    """(assunto, corpo, link mailto:) do e-mail que leva um pedido ao suporte. O pedido não é
    segredo: identifica a instalação (ou o certificado) e o computador, nada mais."""
    import urllib.parse
    dados = ler_pedido(pedido)
    ativacao = pedido.strip().startswith("SCPM-PEDIDO-ATIVACAO.")
    if ativacao:
        assunto = f"S-Cyber: pedido de ativação ({dados.get('instalacao', '?')})"
        o_que = "a ATIVAÇÃO desta instalação do S-Cyber"
    else:
        assunto = f"S-Cyber: credenciamento de certificado ({dados.get('titular') or dados.get('thumbprint', '?')[:8]})"
        o_que = "o CREDENCIAMENTO do meu certificado no S-Cyber"
    corpo = (f"Olá, equipe de suporte do S-Cyber.\n\nSolicito {o_que}.\n\n"
             "Nome:\nUnidade ou empresa:\nTelefone:\n\n"
             f"Pedido (gerado pelo programa, não altere):\n{pedido.strip()}\n\n"
             f"Computador: {dados.get('computador') or '?'} | Conta: {dados.get('conta') or '?'}\n")
    link = (f"mailto:{para}?subject={urllib.parse.quote(assunto)}"
            f"&body={urllib.parse.quote(corpo.replace(chr(10), chr(13) + chr(10)))}")
    return assunto, corpo, link


def ler_pedido(texto):
    texto = "".join((texto or "").split())        # quebras de linha do WhatsApp/e-mail não atrapalham
    for prefixo in ("SCPM-PEDIDO-ATIVACAO.", "SCPM-PEDIDO-CERTIFICADO."):
        if texto.startswith(prefixo):
            corpo = texto[len(prefixo):]
            return json.loads(base64.urlsafe_b64decode(corpo + "=" * (-len(corpo) % 4)))
    raise ValueError("Pedido em formato desconhecido.")


# ------------------------------------------------------------------ chave de ativação
def para_chave(bruto: bytes) -> str:
    return PREFIXO_CHAVE + base64.urlsafe_b64encode(bruto).decode("ascii").rstrip("=")


def de_chave(texto: str) -> bytes:
    texto = "".join(texto.split())
    if texto.startswith("{"):
        return texto.encode("utf-8")
    if not texto.startswith(PREFIXO_CHAVE):
        raise ErroLicenca("invalida", "Chave de ativação em formato desconhecido (deve começar com SCPM1.).")
    corpo = texto[len(PREFIXO_CHAVE):]
    try:
        return base64.urlsafe_b64decode(corpo + "=" * (-len(corpo) % 4))
    except ValueError as exc:
        raise ErroLicenca("invalida", "Chave de ativação incompleta ou corrompida.") from exc


# ------------------------------------------------------------------ listas publicadas
def _hoje():
    return datetime.now(timezone.utc).date()


def _baixar(nome, timeout=6):
    req = urllib.request.Request(URL_PUBLICACAO + nome + ".scsig",
                                 headers={"User-Agent": "S-Cyber-PM", "Cache-Control": "no-cache"})
    import modRede                     # raízes do Windows + certifi (Windows recém-instalado)
    with modRede.abrir(req, timeout) as resp:
        return resp.read(512 * 1024)


class Publicacao:
    """Listas assinadas (administradores, revogações, credenciamentos) com cache local
    e cópia que acompanha o instalador. Vale a de MAIOR sequência que confere."""

    def __init__(self, pasta_cache=None, pasta_pacote=None, baixar=_baixar, online=True, lembrar=True):
        # lembrar=False: só leitura (ferramenta do administrador): não grava cache nem sequências.
        self.lembrar = lembrar
        self.cache = Path(pasta_cache or pasta_instalacao() / "licencas")
        self.pacote = Path(pasta_pacote) if pasta_pacote else Path(__file__).resolve().parent / "licencas"
        self.baixar = baixar
        self.online = online
        self.origem = {}           # nome -> 'online' | 'cache' | 'pacote'
        self.recusadas = {}        # nome -> motivo de uma cópia recusada (vencida ou antiga)
        self.falha_rede = None
        self._admins = None
        self._docs = {}

    def _candidatos(self, nome):
        out = []
        if self.online and not self.falha_rede:      # sem rede: não espera de novo a cada lista
            try:
                out.append(("online", self.baixar(nome)))
            except urllib.error.HTTPError:
                pass                                   # lista ainda não publicada (404): segue
            except (urllib.error.URLError, OSError, ValueError) as exc:
                self.falha_rede = str(getattr(exc, "reason", exc))
        for origem, pasta in (("cache", self.cache), ("pacote", self.pacote)):
            try:
                out.append((origem, (pasta / f"{nome}.scsig").read_bytes()))
            except OSError:
                pass
        return out

    def _sequencias_vistas(self):
        try:
            return {k: int(v) for k, v in json.loads((self.cache / SEQUENCIAS_VISTAS).read_text("utf-8")).items()}
        except (OSError, ValueError, AttributeError, TypeError):
            return {}

    def _lembrar_sequencia(self, nome, sequencia):
        vistas = self._sequencias_vistas()
        if not self.lembrar or sequencia <= vistas.get(nome, 0):
            return
        vistas[nome] = sequencia
        try:
            self.cache.mkdir(parents=True, exist_ok=True)
            (self.cache / SEQUENCIAS_VISTAS).write_text(json.dumps(vistas, sort_keys=True), encoding="utf-8")
        except OSError:
            pass

    def _melhor(self, nome, admins, tipo, so_vigente=False):
        """A lista de MAIOR sequência que confere. Anti-retorno: uma lista com sequência MENOR que a
        maior já aceita neste computador é recusada, mesmo assinada (cópia antiga que ainda tinha um
        administrador removido ou um certificado depois revogado). so_vigente: ignora listas vencidas."""
        minima = self._sequencias_vistas().get(nome, 0)
        hoje = _hoje().isoformat()
        melhor = None
        for origem, bruto in self._candidatos(nome):
            try:
                conteudo, info = abrir(bruto, admins)
            except ErroLicenca:
                continue
            seq = int(conteudo.get("sequencia", 0))
            if conteudo.get("tipo") != tipo or seq < minima:
                if conteudo.get("tipo") == tipo:
                    self.recusadas[nome] = f"cópia antiga recusada (sequência {seq} < {minima})"
                continue
            if so_vigente and hoje > conteudo.get("valida_ate", ""):
                self.recusadas[nome] = f"lista vencida em {conteudo.get('valida_ate')} recusada"
                continue
            if melhor is None or seq > int(melhor[0].get("sequencia", 0)):
                melhor = (conteudo, info, origem, bruto)
        if melhor:
            self.origem[nome] = melhor[2]
            self._lembrar_sequencia(nome, int(melhor[0].get("sequencia", 0)))
            if melhor[2] == "online" and self.lembrar:
                try:
                    self.cache.mkdir(parents=True, exist_ok=True)
                    (self.cache / f"{nome}.scsig").write_bytes(melhor[3])
                except OSError:
                    pass
        return melhor

    def administradores(self):
        """Administradores em vigor. Só vale a lista VIGENTE (não vencida): uma cópia antiga, ainda
        assinada, não pode continuar autorizando um administrador removido. Sem lista vigente, valem
        só os administradores fixos do programa (remover um destes exige uma versão nova)."""
        if self._admins is None:
            admins = dict(ADMINISTRADORES_FIXOS)
            m = self._melhor("administradores", admins, "administradores", so_vigente=True)
            if m and m[0].get("administradores"):
                admins = {k.upper(): v for k, v in m[0]["administradores"].items()}
            self._admins = admins
        return self._admins

    def documento(self, nome):
        """Conteúdo conferido da lista, ou None. Levanta ErroLicenca se a lista venceu."""
        if nome not in self._docs:
            m = self._melhor(nome, self.administradores(), nome)
            self._docs[nome] = m[0] if m else None
        return self._docs[nome]

    def vigente(self, nome, hoje=None):
        doc = self.documento(nome)
        if doc is None and nome in self.recusadas:
            raise ErroLicenca("sem_lista", f"Só há uma cópia não aceita da lista de {nome} neste computador "
                                           f"({self.recusadas[nome]}). Conecte o computador à internet para "
                                           "baixar a atual; se continuar, avise o administrador.")
        if doc is None:
            raise ErroLicenca("sem_lista", f"A lista de {nome} não foi encontrada (sem internet e sem cópia "
                                           "local). Conecte o computador à internet e tente de novo.")
        if (hoje or _hoje()).isoformat() > doc.get("valida_ate", ""):
            raise ErroLicenca("lista_vencida", f"A lista de {nome} venceu em {doc.get('valida_ate')}. "
                                               "Conecte à internet para baixar a atual; se continuar, avise o "
                                               "administrador (a lista precisa ser republicada).")
        return doc


def situacao_listas(publicacao, hoje=None):
    """[(nome, válida_até ou '', dias restantes ou None)] das listas conferidas. Dias negativos =
    vencida. Serve para avisar ANTES de vencer: com a lista de revogações vencida, nenhuma
    instalação consegue conferir a licença até o administrador republicar."""
    hoje = hoje or _hoje()
    out = []
    for nome in LISTAS:
        try:
            doc = publicacao.documento(nome)
        except ErroLicenca:
            doc = None
        ate = (doc or {}).get("valida_ate", "")
        try:
            dias = (date.fromisoformat(ate) - hoje).days if ate else None
        except ValueError:
            dias = None
        out.append((nome, ate, dias))
    return out


def aviso_listas(publicacao, hoje=None, limite=AVISO_LISTA_DIAS):
    """Texto de aviso quando alguma lista vence em até `limite` dias (ou já venceu), ou ''."""
    perto = [(n, a, d) for n, a, d in situacao_listas(publicacao, hoje) if d is not None and d <= limite]
    if not perto:
        return ""
    dias = min(d for _, _, d in perto)
    quando = (f"venceu há {-dias} dia(s)" if dias < 0 else "vence HOJE" if dias == 0 else
              f"vence em {dias} dia(s)")
    return (f"A lista de licenças {quando} ({', '.join(f'{n} até {a}' for n, a, _ in perto)}). Avise o "
            "administrador para republicar (admin_licencas.py publicar); depois do vencimento, as instalações "
            "deixam de conferir a licença.")


# ------------------------------------------------------------------ licença
def conferir_licenca(bruto: bytes, inst, publicacao, hoje=None):
    """Devolve o conteúdo da licença; levanta ErroLicenca com o motivo."""
    hoje = hoje or _hoje()
    licenca, info = abrir(bruto, publicacao.administradores())
    if licenca.get("tipo") != "licenca":
        raise ErroLicenca("invalida", "Este documento não é uma licença.")
    if licenca.get("instalacao") != inst["id"] or licenca.get("maquina") != inst["maquina"]:
        raise ErroLicenca("outra_instalacao", "Esta licença foi emitida para OUTRA instalação ou máquina. "
                                              "Peça a transferência ao administrador.")
    if hoje.isoformat() > licenca.get("valida_ate", ""):
        raise ErroLicenca("expirada", f"A licença venceu em {licenca.get('valida_ate')}. Peça a renovação.")
    revog = publicacao.vigente("revogacoes", hoje)
    if licenca["licenca_id"] in {r.get("licenca_id") for r in revog.get("revogadas", [])}:
        raise ErroLicenca("revogada", "Esta licença foi REVOGADA pelo administrador.")
    licenca["_assinada_por"] = info["administrador"]
    return licenca


def arquivo_licenca(pasta=None):
    return Path(pasta or pasta_instalacao()) / "licenca.sclic"


def estado(pasta=None, publicacao=None, hoje=None):
    """(ok, licença ou None, ErroLicenca ou None) da instalação."""
    inst = instalacao(pasta)
    publicacao = publicacao or Publicacao(pasta_cache=Path(pasta or pasta_instalacao()) / "licencas")
    try:
        bruto = de_chave(arquivo_licenca(pasta).read_text(encoding="utf-8"))
    except OSError:
        return False, None, ErroLicenca("ausente", "Esta instalação ainda não foi ativada.")
    except ErroLicenca as exc:
        return False, None, exc
    try:
        return True, conferir_licenca(bruto, inst, publicacao, hoje), None
    except ErroLicenca as exc:
        return False, None, exc


def ativar(texto, pasta=None, publicacao=None, hoje=None):
    """Confere e guarda a chave de ativação colada pelo usuário. Devolve a licença."""
    inst = instalacao(pasta)
    publicacao = publicacao or Publicacao(pasta_cache=Path(pasta or pasta_instalacao()) / "licencas")
    bruto = de_chave(texto)
    licenca = conferir_licenca(bruto, inst, publicacao, hoje)
    arq = arquivo_licenca(pasta)
    arq.parent.mkdir(parents=True, exist_ok=True)
    arq.write_text(para_chave(bruto), encoding="utf-8")
    return licenca


# ------------------------------------------------------------------ credenciamento
def credenciados(publicacao, hoje=None):
    """{thumb: {'titular', 'papel'}} dos certificados credenciados e não revogados.
    Lista ausente/vencida: vazio (vale só a lista fixa do appSCyberPM.py)."""
    try:
        doc = publicacao.vigente("credenciamentos", hoje)
    except ErroLicenca:
        return {}
    revog = {t.upper() for t in doc.get("revogados", [])}
    out = {}
    for c in doc.get("certificados", []):
        t = str(c.get("thumbprint", "")).upper()
        if len(t) == 40 and t not in revog:
            out[t] = {"titular": c.get("titular", ""), "papel": c.get("papel", "usuario")}
    return out


def papel(thumb, publicacao, hoje=None):
    thumb = (thumb or "").upper()
    if thumb in publicacao.administradores():
        return "administrador"
    return credenciados(publicacao, hoje).get(thumb, {}).get("papel", "usuario")


def nova_validade(dias=VALIDADE_LISTA_DIAS, hoje=None):
    return ((hoje or _hoje()) + timedelta(days=dias)).isoformat()


def hoje_iso():
    return _hoje().isoformat()


def hoje_data():
    return date.today()
