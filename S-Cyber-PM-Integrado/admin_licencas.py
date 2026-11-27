"""Ferramenta dos ADMINISTRADORES (SGT Gabriel Silveira Lima e MAJ Leonídio).

NÃO vai no instalador. Roda no Windows do administrador e assina com o certificado
administrativo dele (chave não exportável); quem não tem um certificado da lista de
administradores é recusado — e, mesmo que alguém altere este script, o aplicativo
recusa qualquer documento que não tenha sido assinado por um administrador.

Uso (PowerShell, na pasta S-Cyber-PM-Integrado do repositório):
    .venv\\Scripts\\python.exe admin_licencas.py iniciar
    .venv\\Scripts\\python.exe admin_licencas.py emitir --pedido SCPM-PEDIDO-ATIVACAO.xxx --unidade "1º BPM" --dias 365
    .venv\\Scripts\\python.exe admin_licencas.py renovar --chave licenca.sclic --dias 365
    .venv\\Scripts\\python.exe admin_licencas.py transferir --chave licenca.sclic --pedido SCPM-PEDIDO-ATIVACAO.yyy
    .venv\\Scripts\\python.exe admin_licencas.py revogar --licenca LIC-... --motivo "computador baixado"
    .venv\\Scripts\\python.exe admin_licencas.py credenciar --pedido SCPM-PEDIDO-CERTIFICADO.zzz --papel revisor
    .venv\\Scripts\\python.exe admin_licencas.py descredenciar --thumbprint ABCD...
    .venv\\Scripts\\python.exe admin_licencas.py administradores --adicionar <IMPRESSAO DIGITAL DE 40 CARACTERES> --nome "..."
    .venv\\Scripts\\python.exe admin_licencas.py administradores --pedido pedido_do_novo_admin.txt --nome "CAP Fulano de Tal"
    .venv\\Scripts\\python.exe admin_licencas.py publicar        (renova a validade das listas: faça a cada 3 semanas)
    .venv\\Scripts\\python.exe admin_licencas.py verificar

Depois de cada operação, publique no GitHub (o aplicativo baixa de lá):
    git add licencas ; git commit -m "Licenças: <operação>" ; git push
"""
from __future__ import annotations

import argparse
import re
import secrets
import sys
from datetime import datetime, timedelta
from pathlib import Path

import modLicenca as L

PASTA = Path(__file__).resolve().parent / "licencas"


def pasta_privada_padrao():
    """Registro PRIVADO do administrador (fora do repositório público): nomes de clientes, de
    pessoas e de unidades ficam só aqui."""
    import modCaminhos
    return modCaminhos.pasta_administrador()


def _agora():
    return datetime.now().isoformat(timespec="seconds")


class Admin:
    """Operações; `assinador` e `thumb` vêm do certificado administrativo do Windows."""

    def __init__(self, pasta=PASTA, assinador=None, thumb=None, hoje=None, pasta_privada=None):
        self.pasta = Path(pasta)
        # Pasta pública = repositório (GitHub). Pasta privada = só no computador do administrador.
        # (pasta pública fora do repositório, como nos testes: a privada fica ao lado dela)
        if pasta_privada:
            self.pasta_privada = Path(pasta_privada)
        elif self.pasta.resolve() == PASTA.resolve():
            self.pasta_privada = pasta_privada_padrao()
        else:
            self.pasta_privada = self.pasta.parent / "registro_privado"
        self.hoje = hoje or L.hoje_data()
        self.pub = L.Publicacao(pasta_cache=self.pasta / "_nao_usado", pasta_pacote=self.pasta, online=False,
                                lembrar=False)
        admins = self.pub.administradores()
        if thumb is None:
            thumb = _certificado_admin(admins)
        if thumb.upper() not in admins:
            raise L.ErroLicenca("nao_admin", "Somente os administradores do S-Cyber PM (SGT Gabriel e MAJ "
                                             "Leonídio) podem emitir, renovar, transferir e revogar. O certificado "
                                             f"{thumb[:8]}… não é administrativo.")
        self.thumb = thumb.upper()
        self.nome = admins[self.thumb]
        if assinador is None:
            from formSign import assinar_bytes
            assinador = lambda dados: assinar_bytes(dados, self.thumb)  # noqa: E731
        self.assinador = assinador

    # -------------------------------------------------- listas
    def _lista(self, nome):
        doc = self.pub.documento(nome)
        if doc:
            return dict(doc)
        base = {"tipo": nome, "sequencia": 0}
        if nome == "revogacoes":
            base["revogadas"] = []
        elif nome == "credenciamentos":
            base.update(certificados=[], revogados=[])
        else:
            base["administradores"] = dict(L.ADMINISTRADORES_FIXOS)
        return base

    def _publicar(self, nome, doc):
        if nome == "credenciamentos":
            doc = self._sem_nomes(doc)
        doc = dict(doc, tipo=nome, sequencia=int(doc.get("sequencia", 0)) + 1, emitida_em=_agora(),
                   emitida_por=self.nome,
                   valida_ate=(self.hoje + timedelta(days=L.VALIDADE_LISTA_DIAS)).isoformat())
        self.pasta.mkdir(parents=True, exist_ok=True)
        (self.pasta / f"{nome}.scsig").write_bytes(L.empacotar(doc, self.assinador))
        self.pub._docs.pop(nome, None)
        if nome == "administradores":
            self.pub._admins = None
        return doc

    def _sem_nomes(self, doc):
        """Listas publicadas antes da 2.0.6 tinham o nome do titular de cada certificado. Na próxima
        publicação os nomes saem da lista pública e ficam no registro privado (LGPD, minimização)."""
        certs, retirados = [], []
        for c in doc.get("certificados") or []:
            if c.get("titular"):
                retirados.append(f"{c.get('thumbprint', '')[:8]}… titular {c['titular']}")
                c = dict(c, titular="")
            certs.append(c)
        if retirados:
            self._registrar("minimizar", detalhes=f"{len(retirados)} nome(s) retirado(s) da lista pública",
                            privado="; ".join(retirados))
        return dict(doc, certificados=certs)

    def _registrar(self, operacao, licenca_id="", instalacao="", detalhes="", privado=""):
        """Registro público (repositório): só identificadores, sem nomes de clientes nem de pessoas
        (LGPD, minimização). `privado`: nomes e unidades, gravados só no registro privado local."""
        base = {"tipo": "registro", "operacao": operacao, "quando": _agora(), "administrador": self.nome,
                "certificado": self.thumb, "licenca_id": licenca_id, "instalacao": instalacao}
        linha = L.empacotar(dict(base, detalhes=detalhes), self.assinador)
        self.pasta.mkdir(parents=True, exist_ok=True)
        with open(self.pasta / "registro.jsonl", "ab") as f:
            f.write(linha + b"\n")
        if privado:
            try:
                self.pasta_privada.mkdir(parents=True, exist_ok=True)
                with open(self.pasta_privada / "registro_privado.jsonl", "ab") as f:
                    f.write(L.empacotar(dict(base, detalhes=f"{detalhes}; {privado}"), self.assinador) + b"\n")
            except OSError as e:
                print(f"Aviso: registro privado não gravado ({e}).", file=sys.stderr)

    # -------------------------------------------------- operações
    def iniciar(self):
        feitos = []
        for nome in L.LISTAS:
            if not (self.pasta / f"{nome}.scsig").exists():
                self._publicar(nome, self._lista(nome))
                feitos.append(nome)
        self._registrar("iniciar", detalhes=", ".join(feitos) or "listas já existiam")
        return feitos

    def _licenca(self, instalacao, maquina, unidade, titular, dias, operacao, origem="", modalidade="pm",
                 organizacao=""):
        if not (instalacao and maquina):
            raise L.ErroLicenca("invalida", "Pedido sem instalação ou máquina.")
        if modalidade not in L.MODALIDADES:
            raise L.ErroLicenca("invalida", f"Modalidade inválida: use {', '.join(L.MODALIDADES)}.")
        if not 1 <= int(dias) <= L.PRAZO_MAX_LICENCA_DIAS:
            raise L.ErroLicenca("invalida", f"Prazo da licença deve ficar entre 1 e {L.PRAZO_MAX_LICENCA_DIAS} dias.")
        lic = {"tipo": "licenca", "versao": 1, "licenca_id": "LIC-" + secrets.token_hex(6).upper(),
               "instalacao": instalacao, "maquina": maquina, "unidade": unidade, "titular": titular,
               "emitida_em": _agora(), "valida_ate": (self.hoje + timedelta(days=int(dias))).isoformat(),
               "operacao": operacao, "substitui": origem, "emitida_por": self.nome, "modalidade": modalidade}
        if modalidade == "business":
            # Os dados da empresa ficam numa pasta só dela (modCaminhos.definir_organizacao).
            lic["organizacao"] = (organizacao or unidade or "").strip() or "empresa"
        chave = L.para_chave(L.empacotar(lic, self.assinador))
        self._registrar(operacao, lic["licenca_id"], instalacao,
                        f"{L.MODALIDADES[modalidade]}; até {lic['valida_ate']}"
                        + (f"; substitui {origem}" if origem else ""),
                        privado=f"unidade {unidade}"
                        + (f"; organização {lic['organizacao']}" if lic.get("organizacao") else "")
                        + (f"; titular {titular}" if titular else ""))
        return lic, chave

    def emitir(self, pedido, unidade, titular="", dias=365, modalidade="pm", organizacao=""):
        p = L.ler_pedido(pedido)
        return self._licenca(p["instalacao"], p["maquina"], unidade, titular, dias, "emitir", modalidade=modalidade,
                             organizacao=organizacao)

    def _abrir_chave(self, chave):
        lic, _ = L.abrir(L.de_chave(chave), self.pub.administradores())
        if lic.get("tipo") != "licenca":
            raise L.ErroLicenca("invalida", "Não é uma licença.")
        return lic

    def renovar(self, chave, dias=365):
        lic = self._abrir_chave(chave)
        nova = self._licenca(lic["instalacao"], lic["maquina"], lic.get("unidade", ""), lic.get("titular", ""),
                             dias, "renovar", lic["licenca_id"], L.modalidade(lic), lic.get("organizacao", ""))
        return nova

    def transferir(self, chave, pedido_novo, motivo="transferência"):
        lic = self._abrir_chave(chave)
        p = L.ler_pedido(pedido_novo)
        self.revogar(lic["licenca_id"], f"{motivo} para {p['instalacao']}", lic["instalacao"])
        return self._licenca(p["instalacao"], p["maquina"], lic.get("unidade", ""), lic.get("titular", ""),
                             (datetime.fromisoformat(lic["valida_ate"]).date() - self.hoje).days or 1,
                             "transferir", lic["licenca_id"], L.modalidade(lic), lic.get("organizacao", ""))

    def revogar(self, licenca_id, motivo, instalacao=""):
        doc = self._lista("revogacoes")
        if licenca_id not in {r["licenca_id"] for r in doc.get("revogadas", [])}:
            doc["revogadas"] = list(doc.get("revogadas", [])) + [
                {"licenca_id": licenca_id, "data": _agora(), "motivo": motivo, "por": self.nome}]
        self._publicar("revogacoes", doc)
        self._registrar("revogar", licenca_id, instalacao, motivo)

    def credenciar(self, thumbprint, titular="", papel="usuario", instalacao=""):
        thumbprint = "".join(c for c in thumbprint if c.isalnum()).upper()
        if len(thumbprint) != 40 or any(c not in "0123456789ABCDEF" for c in thumbprint):
            raise L.ErroLicenca("invalida", "Thumbprint inválido (40 caracteres hexadecimais).")
        if papel not in L.PAPEIS:
            raise L.ErroLicenca("invalida", f"Papel deve ser um de: {', '.join(L.PAPEIS)}.")
        doc = self._lista("credenciamentos")
        certs = [c for c in doc.get("certificados", []) if c["thumbprint"] != thumbprint]
        # Lista pública: sem o nome da pessoa (o aplicativo só precisa do thumbprint e do papel).
        certs.append({"thumbprint": thumbprint, "titular": "", "papel": papel, "desde": _agora()})
        doc["certificados"] = certs
        doc["revogados"] = [t for t in doc.get("revogados", []) if t != thumbprint]
        self._publicar("credenciamentos", doc)
        self._registrar("credenciar", "", instalacao, f"{thumbprint[:8]}… papel {papel}",
                        privado=f"titular {titular}" if titular else "")

    def credenciar_pedido(self, pedido, papel="usuario"):
        p = L.ler_pedido(pedido)
        if p.get("algoritmo") and str(p["algoritmo"]).upper() != "RSA":
            raise L.ErroLicenca("invalida", f"O certificado {p['thumbprint'][:8]}… usa chave {p['algoritmo']}, não "
                                            "RSA: ele não funciona no S-Cyber. Peça à pessoa para usar 'Criar meu "
                                            "certificado' e mandar o pedido do certificado novo.")
        return self.credenciar(p["thumbprint"], p.get("titular", ""), papel, p.get("instalacao", ""))

    def descredenciar(self, thumbprint, motivo=""):
        thumbprint = thumbprint.upper()
        doc = self._lista("credenciamentos")
        doc["certificados"] = [c for c in doc.get("certificados", []) if c["thumbprint"] != thumbprint]
        doc["revogados"] = sorted(set(doc.get("revogados", [])) | {thumbprint})
        self._publicar("credenciamentos", doc)
        self._registrar("descredenciar", "", "", f"{thumbprint[:8]}… {motivo}")

    def administradores(self, adicionar=None, nome="", remover=None):
        doc = self._lista("administradores")
        admins = {k.upper(): v for k, v in doc.get("administradores", {}).items()}
        if adicionar:
            adicionar = impressao_valida(adicionar)
            admins[adicionar] = nome or adicionar[:8]
        if remover:
            if remover.upper() == self.thumb:
                raise L.ErroLicenca("invalida", "Um administrador não remove o próprio certificado.")
            admins.pop(remover.upper(), None)
        if not admins:
            raise L.ErroLicenca("invalida", "A lista de administradores não pode ficar vazia.")
        doc["administradores"] = admins
        self._publicar("administradores", doc)
        self._registrar("administradores", "", "", f"+{(adicionar or '')[:8]} -{(remover or '')[:8]}")

    def publicar(self):
        for nome in L.LISTAS:
            self._publicar(nome, self._lista(nome))
        self._registrar("publicar", detalhes=f"listas válidas até {self.hoje + timedelta(days=L.VALIDADE_LISTA_DIAS)}")


def verificar(pasta=PASTA, hoje=None, alerta_dias=L.AVISO_LISTA_DIAS):
    """Confere assinaturas e validade de tudo o que está publicado. Devolve linhas de texto:
    'ERRO' (assinatura ou lista vencida/ausente) e 'AVISO' (vence em até `alerta_dias` dias)."""
    pub = L.Publicacao(pasta_cache=Path(pasta) / "_nao_usado", pasta_pacote=pasta, online=False, lembrar=False)
    out = [f"Administradores: {', '.join(sorted(set(pub.administradores().values())))}"]
    dias = {n: d for n, _, d in L.situacao_listas(pub, hoje)}
    for nome in L.LISTAS:
        try:
            doc = pub.vigente(nome, hoje)
            restam = dias.get(nome)
            rotulo = "AVISO" if restam is not None and restam <= alerta_dias else "OK  "
            out.append(f"{rotulo} {nome}: sequência {doc['sequencia']}, válida até {doc['valida_ate']} "
                       f"({restam} dia(s)), assinada por {doc.get('emitida_por')}"
                       + (" — republique: admin_licencas.py publicar" if rotulo == "AVISO" else ""))
        except L.ErroLicenca as exc:
            out.append(f"ERRO {nome}: {exc}")
    reg = Path(pasta) / "registro.jsonl"
    if reg.exists():
        linhas = [x for x in reg.read_bytes().splitlines() if x.strip()]
        ruins = 0
        for x in linhas:
            try:
                L.abrir(x, pub.administradores())
            except L.ErroLicenca:
                ruins += 1
        out.append(f"{'OK ' if not ruins else 'ERRO'} registro: {len(linhas)} operação(ões), {ruins} com "
                   "assinatura inválida")
    return out


# ------------------------------------------------------------------ apoio à tela do administrador
def extrair_pedido(texto):
    """O pedido dentro de um texto maior: o e-mail inteiro colado, com o pedido quebrado em várias
    linhas pelo programa de e-mail. Vai de 'SCPM-PEDIDO' até a primeira linha em branco."""
    import re
    texto = texto or ""
    inicio = texto.find("SCPM-PEDIDO")
    if inicio < 0:
        return "".join(texto.split())
    trecho = re.split(r"\n\s*\n|Computador:", texto[inicio:].replace("\r\n", "\n"), maxsplit=1)[0]
    return "".join(trecho.split())


def thumb_do_pedido(texto, nome=""):
    """(impressão digital, nome) de um pedido de CREDENCIAMENTO de certificado (pode ser o e-mail inteiro).
    Para adicionar um administrador sem digitar os 40 caracteres da impressão digital."""
    try:
        dados = L.ler_pedido(extrair_pedido(texto))
    except (ValueError, TypeError) as exc:
        raise L.ErroLicenca("invalida", "Não reconheci o pedido de credenciamento do certificado.") from exc
    thumb = "".join(c for c in str(dados.get("thumbprint", "")) if c.isalnum()).upper()
    if not thumb:
        raise L.ErroLicenca("invalida", "Esse é um pedido de ATIVAÇÃO; para administrador, use o pedido de "
                                        "credenciamento do CERTIFICADO.")
    return thumb, (nome or dados.get("titular", "")).strip()


def resumo_pedido(texto):
    """Lê um pedido colado (de ativação ou de certificado), sozinho ou dentro do e-mail inteiro, e
    diz o que é. ValueError se não for."""
    limpo = extrair_pedido(texto)
    try:
        dados = L.ler_pedido(limpo)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("Isto não é um pedido do S-Cyber. Ele começa com SCPM-PEDIDO-ATIVACAO. ou "
                         "SCPM-PEDIDO-CERTIFICADO. Peça para a pessoa copiar de novo pelo botão da tela.") from exc
    if not isinstance(dados, dict):
        raise ValueError("Pedido incompleto: peça para copiar de novo.")
    origem = f"computador {dados.get('computador') or '?'}, conta {dados.get('conta') or '?'}"
    if limpo.startswith("SCPM-PEDIDO-ATIVACAO."):
        if not (dados.get("instalacao") and dados.get("maquina")):
            raise ValueError("Pedido de ativação incompleto: peça para copiar de novo.")
        return {"tipo": "ativacao", "pedido": limpo, "dados": dados,
                "texto": f"Pedido de ATIVAÇÃO da instalação {dados['instalacao']} ({origem}, versão "
                         f"{dados.get('versao') or '?'})."}
    if not dados.get("thumbprint"):
        raise ValueError("Pedido de certificado incompleto: peça para copiar de novo.")
    texto = (f"Pedido de CREDENCIAMENTO do certificado {dados['thumbprint'][:8]}… de "
             f"{dados.get('titular') or '?'} ({origem}, instalação {dados.get('instalacao') or '?'}).")
    alg = str(dados.get("algoritmo") or "")
    if alg and alg.upper() != "RSA":
        texto += f" ATENÇÃO: chave {alg}, não RSA — NÃO serve ao S-Cyber; peça um certificado criado pelo programa."
    elif _parece_da_organizacao(dados.get("titular")):
        texto += (" ATENÇÃO: o titular é um código (CN=<GUID>), não o nome de uma pessoa — parece um certificado "
                  "do Windows ou da organização. Confirme com a pessoa antes de credenciar.")
    return {"tipo": "certificado", "pedido": limpo, "dados": dados, "texto": texto}



def _parece_da_organizacao(titular):
    from modDiagnostico import parece_da_organizacao
    return parece_da_organizacao(str(titular or ""))


def resposta_licenca(lic, chave):
    """Texto para responder ao e-mail do pedido: instruções curtas + a chave."""
    produto = L.MODALIDADES[L.modalidade(lic)]
    return (f"Olá! Sua licença do {produto} foi emitida.\n\n"
            f"Licença: {lic['licenca_id']} | Instalação: {lic['instalacao']} | Válida até: {lic['valida_ate']}\n\n"
            "Como ativar:\n1. Abra o S-Cyber neste mesmo computador.\n"
            "2. Copie a CHAVE abaixo inteira (de SCPM1. até o fim) e cole na tela de ativação.\n"
            "3. Clique em Ativar.\n\nCHAVE DE ATIVAÇÃO:\n"
            f"{chave}\n\nEquipe de suporte do S-Cyber ({L.EMAIL_SUPORTE})\n")


def nome_arquivo(lic):
    return f"licenca_{lic['instalacao']}.sclic"


CAMINHO_LISTAS = Path("S-Cyber-PM-Integrado") / "licencas"     # onde as listas ficam dentro do clone


def _url_origem(raiz):
    """URL do remoto 'origin' lida do .git/config (sem rodar o Git). '' se não der para ler."""
    git = raiz / ".git"
    try:
        if git.is_file():                    # worktree ou submódulo: o .git é um arquivo "gitdir: ..."
            git = (raiz / git.read_text(encoding="utf-8").split(":", 1)[1].strip()).resolve()
            if (git / "commondir").exists():
                git = (git / (git / "commondir").read_text(encoding="utf-8").strip()).resolve()
        texto = (git / "config").read_text(encoding="utf-8", errors="replace")
    except (OSError, IndexError):
        return ""
    m = re.search(r'\[remote "origin"\][^\[]*?^\s*url\s*=\s*(\S+)', texto, re.M)
    return m.group(1) if m else ""


def _e_o_repositorio(url):
    u = url.strip().lower().replace(":", "/").rstrip("/")
    u = u[:-4] if u.endswith(".git") else u
    return u.endswith("/" + L.REPOSITORIO.lower())


def situacao_git(pasta=PASTA):
    """(raiz do clone do S-Cyber, '') ou (None, motivo). O repositório que vale é o MAIS PRÓXIMO
    acima da pasta (o mesmo que o Git usaria). Não basta achar um .git: uma pasta de ZIP extraída
    dentro de outro repositório seria tratada como clone e o Git operaria no repositório errado.
    Exige a pasta das listas no caminho esperado e o 'origin' apontando para o repositório do S-Cyber."""
    pasta = Path(pasta).resolve()
    for p in [pasta, *pasta.parents]:
        if (p / ".git").exists():
            if pasta != (p / CAMINHO_LISTAS).resolve():
                return None, (f"esta pasta está dentro de outro repositório Git ({p}), não no lugar das listas "
                              f"de um clone do S-Cyber ({CAMINHO_LISTAS.as_posix()})")
            if not _e_o_repositorio(_url_origem(p)):
                return None, (f"o clone em {p} não é do repositório {L.REPOSITORIO} (confira o 'origin' com "
                              "'git remote -v')")
            return p, ""
    return None, "esta pasta não é um clone do Git (veio de um ZIP)"


def raiz_git(pasta=PASTA):
    """Raiz do clone do repositório do S-Cyber que contém a pasta das listas, ou None."""
    return situacao_git(pasta)[0]


def pagina_de_envio():
    """Página do GitHub para enviar as listas pelo navegador, sem Git (pasta de ZIP)."""
    return f"https://github.com/{L.REPOSITORIO}/upload/main/S-Cyber-PM-Integrado/licencas"


def ja_credenciado(adm, pedido, papel):
    """True se o certificado do pedido já está credenciado com esse papel nas listas desta pasta."""
    dados = L.ler_pedido(extrair_pedido(pedido))
    thumb = "".join(c for c in dados.get("thumbprint", "") if c.isalnum()).upper()
    for c in (adm._lista("credenciamentos").get("certificados") or []):
        if c.get("thumbprint") == thumb and c.get("papel") == papel:
            return True
    return False


def _juntar_e_reenviar(raiz, executar, saida):
    """O GitHub tem algo mais novo (outra pasta de administração enviou antes). Junta com
    'git pull --rebase' e envia de novo. O registro.jsonl se junta sozinho (merge=union no
    .gitattributes). Se a MESMA lista assinada mudou dos dois lados, não dá para juntar: desfaz e
    explica, sem perder nada do que está no GitHub."""
    import subprocess

    def git(*args):
        return executar(["git", "-C", str(raiz), *args], capture_output=True, text=True, timeout=180)
    try:
        r = git("pull", "--rebase", "--autostash")
        if r.returncode != 0:
            conflito = "CONFLICT" in ((r.stdout or "") + (r.stderr or ""))
            git("rebase", "--abort")
            if not conflito:
                return False, "Não foi possível juntar com o GitHub.\n" + ((r.stdout or "") + (r.stderr or "")).strip()
            return False, (
                "Outra pasta de administração alterou a mesma lista no GitHub, e listas assinadas não podem ser "
                "misturadas. Faça assim, na pasta do repositório:\n"
                "  git fetch\n  git reset --hard origin/main\n"
                "Depois, abra esta tela de novo e REFAÇA a última operação (a licença já enviada continua "
                "valendo; só o credenciamento ou a renovação precisam ser refeitos).")
        r = git("push")
    except subprocess.TimeoutExpired:
        return False, "O GitHub demorou demais para responder. Tente de novo."
    texto = ((r.stdout or "") + (r.stderr or "")).strip()
    if r.returncode != 0:
        return False, "Falhou em 'git push' depois de juntar com o GitHub.\n" + texto
    return True, ("O GitHub tinha uma atualização mais nova (de outra pasta de administração): juntei as duas e "
                  "enviei. Em alguns minutos vale em todos os computadores.")


def publicar_no_github(pasta=PASTA, mensagem="Licenças: atualização", executar=None):
    """git add/commit/push só da pasta das listas. Devolve (ok, texto para mostrar)."""
    import subprocess
    executar = executar or subprocess.run
    raiz, motivo = situacao_git(pasta)
    if raiz is None:
        return False, (f"Não dá para enviar daqui: {motivo}. Copie a pasta 'licencas' para um clone do "
                       "repositório do S-Cyber e envie de lá.")
    rel = str(Path(pasta).resolve().relative_to(raiz))
    pendente = operacao_pendente(raiz)
    if pendente:
        return False, (f"Não dá para enviar: a pasta do repositório ficou no meio de uma {pendente} que não "
                       f"terminou (por exemplo, um 'git pull' com conflito).\n\n{CONSERTAR_PASTA}")
    try:
        situacao = executar(["git", "-C", str(raiz), "status", "--porcelain", "--", rel],
                            capture_output=True, text=True, timeout=60)
    except FileNotFoundError:
        return False, "O Git não está instalado neste computador (https://git-scm.com)."
    except subprocess.TimeoutExpired:
        return False, "O Git demorou demais para responder. Tente de novo."
    nada_novo = situacao.returncode == 0 and not (situacao.stdout or "").strip()
    # Só a pasta das listas: outros arquivos alterados no clone não entram no envio.
    passos = ((["git", "-C", str(raiz), "push"],) if nada_novo else
              (["git", "-C", str(raiz), "add", "--", rel],
               ["git", "-C", str(raiz), "commit", "-m", mensagem, "--", rel],
               ["git", "-C", str(raiz), "push"]))
    saida = []
    for cmd in passos:
        try:
            r = executar(cmd, capture_output=True, text=True, timeout=180)
        except FileNotFoundError:
            return False, "O Git não está instalado neste computador (https://git-scm.com)."
        except subprocess.TimeoutExpired:
            return False, "O Git demorou demais para responder. Confira a internet e tente de novo."
        saida.append(((r.stdout or "") + (r.stderr or "")).strip())
        if r.returncode != 0:
            if cmd[3] == "commit" and ("nothing" in saida[-1].lower() or "no changes" in saida[-1].lower()):
                saida[-1] = "Nada novo para enviar."
                continue
            if cmd[3] == "push" and ("rejected" in saida[-1] or "fetch first" in saida[-1]):
                return _juntar_e_reenviar(raiz, executar, saida)
            return False, f"Falhou em 'git {cmd[3]}'.\n" + "\n".join(x for x in saida if x)
    if nada_novo:
        return True, "Nada novo para enviar: as listas desta pasta já estão no GitHub."
    return True, "Enviado ao GitHub. Em alguns minutos vale em todos os computadores.\n" + \
        "\n".join(x for x in saida if x)


def impressao_valida(texto):
    """Impressão digital (SHA-1) de um certificado: 40 caracteres de 0-9 e A-F. Espaços e dois-pontos
    são aceitos e removidos. Qualquer outra coisa é recusada: um texto de exemplo copiado por engano
    não pode virar administrador."""
    import re
    limpo = re.sub(r"[\s:]", "", texto or "").upper()
    if not re.fullmatch(r"[0-9A-F]{40}", limpo):
        raise L.ErroLicenca("invalida", f"Impressão digital inválida: {texto!r}. Ela tem 40 caracteres de 0 a 9 "
                                        "e A a F (veja em certmgr.msc → certificado → Detalhes → Impressão digital).")
    return limpo


CONSERTAR_PASTA = ("Para deixar a pasta igual ao GitHub (o que já foi enviado não se perde), rode na pasta do "
                   "repositório, um comando por vez:\n  git merge --abort\n  git rebase --abort\n  git fetch\n"
                   "  git reset --hard origin/main\n(Os dois primeiros podem dizer que não há nada a desfazer: tudo "
                   "bem.) Depois, abra esta tela de novo e refaça só a operação que ainda não aparece no GitHub.")


def operacao_pendente(raiz):
    """Junção (merge) ou rebase que parou no meio, por exemplo um 'git pull' com conflito."""
    git = Path(raiz) / ".git"
    if (git / "MERGE_HEAD").exists():
        return "junção (merge)"
    if (git / "rebase-merge").exists() or (git / "rebase-apply").exists():
        return "rebase"
    return None


def sincronizar(pasta=PASTA, executar=None):
    """Traz do GitHub as listas mais novas ANTES de operar (git pull --ff-only), para não assinar
    em cima de uma lista velha. Devolve (ok, texto). Pasta sem Git: (True, '') — nada a fazer."""
    import subprocess
    executar = executar or subprocess.run
    raiz = raiz_git(pasta)
    if raiz is None:
        return True, ""
    pendente = operacao_pendente(raiz)
    if pendente:
        return False, f"A pasta do repositório ficou no meio de uma {pendente} que não terminou.\n\n{CONSERTAR_PASTA}"
    try:
        r = executar(["git", "-C", str(raiz), "pull", "--ff-only", "--autostash"], capture_output=True, text=True,
                     timeout=120)
    except FileNotFoundError:
        return False, "O Git não está instalado: não deu para conferir se as listas estão atualizadas."
    except subprocess.TimeoutExpired:
        return False, "O GitHub não respondeu: confira a internet antes de emitir ou credenciar."
    saida = ((r.stdout or "") + (r.stderr or "")).strip()
    if r.returncode != 0:
        return False, ("Não foi possível atualizar a pasta com o GitHub. Antes de emitir ou credenciar, rode na "
                       f"pasta do repositório: git pull\n\n{saida[-600:]}")
    return True, "Atualizado com o GitHub." if "Already up to date" not in saida else "Já estava atualizado."


def _certificado_admin(admins):
    """Primeiro certificado administrativo com chave privada no Windows deste usuário."""
    from modDiagnostico import listar_certificados
    for c in listar_certificados():
        if c["thumb"] in admins and c["chave_privada"]:
            return c["thumb"]
    raise L.ErroLicenca("nao_admin", "Nenhum certificado de ADMINISTRADOR com chave privada neste usuário do "
                                     "Windows. Só o SGT Gabriel e o MAJ Leonídio emitem licenças.")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Licenças do S-Cyber PM (somente administradores)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("iniciar")
    e = sub.add_parser("emitir")
    e.add_argument("--pedido", required=True)
    e.add_argument("--unidade", required=True)
    e.add_argument("--titular", default="")
    e.add_argument("--dias", type=int, default=365)
    e.add_argument("--modalidade", choices=list(L.MODALIDADES), default="pm",
                   help="business = S-Cyber Business (empresas, sem integrações da PM); pm = S-Cyber PM")
    e.add_argument("--organizacao", default="",
                   help="business: nome da empresa (os dados dela ficam numa pasta só dela); padrão = --unidade")
    e.add_argument("--saida")
    r = sub.add_parser("renovar")
    r.add_argument("--chave", required=True, help="arquivo .sclic ou o texto SCPM1....")
    r.add_argument("--dias", type=int, default=365)
    r.add_argument("--saida")
    t = sub.add_parser("transferir")
    t.add_argument("--chave", required=True)
    t.add_argument("--pedido", required=True)
    t.add_argument("--saida")
    v = sub.add_parser("revogar")
    v.add_argument("--licenca", required=True)
    v.add_argument("--motivo", required=True)
    c = sub.add_parser("credenciar")
    c.add_argument("--pedido")
    c.add_argument("--thumbprint")
    c.add_argument("--titular", default="")
    c.add_argument("--papel", default="usuario", choices=L.PAPEIS)
    d = sub.add_parser("descredenciar")
    d.add_argument("--thumbprint", required=True)
    d.add_argument("--motivo", default="")
    a = sub.add_parser("administradores")
    a.add_argument("--adicionar", help="impressão digital (40 caracteres) do certificado do novo administrador")
    a.add_argument("--pedido", default="",
                   help="OU o pedido de credenciamento do certificado do novo administrador (texto, arquivo ou "
                        "o e-mail inteiro): a impressão digital sai dele, sem digitar")
    a.add_argument("--nome", default="", help='nome que aparece na tela, ex.: "MAJ Leonídio Alves de Moraes Junior"')
    a.add_argument("--remover")
    sub.add_parser("publicar")
    vf = sub.add_parser("verificar", help="confere assinaturas e validade (não precisa de certificado)")
    vf.add_argument("--alerta-dias", type=int, default=L.AVISO_LISTA_DIAS,
                    help="avisa (e sai com código 1) quando uma lista vence em até N dias")
    args = ap.parse_args(argv)

    if args.cmd == "verificar":
        linhas = verificar(alerta_dias=args.alerta_dias)
        print("\n".join(linhas))
        return 1 if any(x.startswith(("ERRO", "AVISO")) for x in linhas) else 0
    try:
        adm = Admin()
        print(f"Administrador: {adm.nome} (certificado {adm.thumb[:8]}…)")
        lic = chave = None
        if args.cmd == "iniciar":
            print("Listas criadas:", adm.iniciar() or "nenhuma (já existiam)")
            print("\n".join(x for x in verificar(adm.pasta) if not x.startswith("Administradores")))
        elif args.cmd == "emitir":
            lic, chave = adm.emitir(args.pedido, args.unidade, args.titular, args.dias, args.modalidade,
                                    args.organizacao)
        elif args.cmd == "renovar":
            lic, chave = adm.renovar(_texto(args.chave), args.dias)
        elif args.cmd == "transferir":
            lic, chave = adm.transferir(_texto(args.chave), args.pedido)
        elif args.cmd == "revogar":
            adm.revogar(args.licenca, args.motivo)
            print(f"Licença {args.licenca} revogada.")
        elif args.cmd == "credenciar":
            if args.pedido:
                adm.credenciar_pedido(args.pedido, args.papel)
            else:
                adm.credenciar(args.thumbprint or "", args.titular, args.papel)
            print("Certificado credenciado.")
        elif args.cmd == "descredenciar":
            adm.descredenciar(args.thumbprint, args.motivo)
            print("Certificado descredenciado.")
        elif args.cmd == "administradores":
            adicionar, nome = args.adicionar, args.nome
            if args.pedido:
                adicionar, nome = thumb_do_pedido(_texto(args.pedido), nome)
            adm.administradores(adicionar, nome, args.remover)
            print("Lista de administradores atualizada:")
            for thumb, quem in sorted(adm.pub.administradores().items(), key=lambda x: x[1]):
                print(f"  {quem}  ({thumb[:8]}…)")
            print("Agora ENVIE AO GITHUB (botão 'Enviar ao GitHub' na tela, ou git add/commit/push da pasta licencas).")
        elif args.cmd == "publicar":
            adm.publicar()
            print(f"Listas republicadas, válidas por {L.VALIDADE_LISTA_DIAS} dias.")
        if chave:
            print(f"Licença {lic['licenca_id']} para {lic['instalacao']}, válida até {lic['valida_ate']}.")
            if getattr(args, "saida", None):
                Path(args.saida).write_text(chave, encoding="utf-8")
                print(f"Chave gravada em {args.saida} (envie ao usuário).")
            else:
                print("\nCHAVE DE ATIVAÇÃO (envie ao usuário):\n" + chave)
        print("\n" + _como_publicar(args.cmd))
        return 0
    except (L.ErroLicenca, ValueError, KeyError) as exc:
        print(f"ERRO: {exc}", file=sys.stderr)
        return 2


MUDAM_LISTAS = ("iniciar", "revogar", "credenciar", "descredenciar", "administradores", "publicar")


def _como_publicar(cmd, raiz=None):
    """O que fazer depois da operação. Só as listas precisam chegar ao GitHub para valer nas outras
    instalações; a emissão, a renovação e a transferência acrescentam só uma linha ao registro."""
    raiz = Path(raiz) if raiz else PASTA.parent.parent
    clone, motivo = situacao_git(raiz / CAMINHO_LISTAS)
    comando = f'git add licencas ; git commit -m "Licenças: {cmd}" ; git push'
    if cmd in MUDAM_LISTAS:
        inicio = "PUBLIQUE para valer nas outras instalações"
    else:
        inicio = ("A licença já pode ser enviada ao usuário. Para guardar o registro desta operação no GitHub "
                  "(recomendado)")
    if clone:
        return f"{inicio}: {comando}"
    return (f"{inicio}: {motivo}. Copie a pasta licencas para um clone do repositório do S-Cyber e rode lá: "
            f"{comando}")


def _texto(valor):
    p = Path(valor)
    try:
        if p.is_file():
            return p.read_text(encoding="utf-8")
    except OSError:
        pass
    return valor


if __name__ == "__main__":
    sys.exit(main())
