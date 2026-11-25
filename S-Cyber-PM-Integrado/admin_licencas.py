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
    .venv\\Scripts\\python.exe admin_licencas.py administradores --adicionar THUMB --nome "SGT Gabriel (novo cert.)"
    .venv\\Scripts\\python.exe admin_licencas.py publicar        (renova a validade das listas: faça a cada 3 semanas)
    .venv\\Scripts\\python.exe admin_licencas.py verificar

Depois de cada operação, publique no GitHub (o aplicativo baixa de lá):
    git add licencas ; git commit -m "Licenças: <operação>" ; git push
"""
from __future__ import annotations

import argparse
import secrets
import sys
from datetime import datetime, timedelta
from pathlib import Path

import modLicenca as L

PASTA = Path(__file__).resolve().parent / "licencas"


def _agora():
    return datetime.now().isoformat(timespec="seconds")


class Admin:
    """Operações; `assinador` e `thumb` vêm do certificado administrativo do Windows."""

    def __init__(self, pasta=PASTA, assinador=None, thumb=None, hoje=None):
        self.pasta = Path(pasta)
        self.hoje = hoje or L.hoje_data()
        self.pub = L.Publicacao(pasta_cache=self.pasta / "_nao_usado", pasta_pacote=self.pasta, online=False)
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
        doc = dict(doc, tipo=nome, sequencia=int(doc.get("sequencia", 0)) + 1, emitida_em=_agora(),
                   emitida_por=self.nome,
                   valida_ate=(self.hoje + timedelta(days=L.VALIDADE_LISTA_DIAS)).isoformat())
        self.pasta.mkdir(parents=True, exist_ok=True)
        (self.pasta / f"{nome}.scsig").write_bytes(L.empacotar(doc, self.assinador))
        self.pub._docs.pop(nome, None)
        if nome == "administradores":
            self.pub._admins = None
        return doc

    def _registrar(self, operacao, licenca_id="", instalacao="", detalhes=""):
        linha = L.empacotar({"tipo": "registro", "operacao": operacao, "quando": _agora(),
                             "administrador": self.nome, "certificado": self.thumb, "licenca_id": licenca_id,
                             "instalacao": instalacao, "detalhes": detalhes}, self.assinador)
        self.pasta.mkdir(parents=True, exist_ok=True)
        with open(self.pasta / "registro.jsonl", "ab") as f:
            f.write(linha + b"\n")

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
        lic = {"tipo": "licenca", "versao": 1, "licenca_id": "LIC-" + secrets.token_hex(6).upper(),
               "instalacao": instalacao, "maquina": maquina, "unidade": unidade, "titular": titular,
               "emitida_em": _agora(), "valida_ate": (self.hoje + timedelta(days=int(dias))).isoformat(),
               "operacao": operacao, "substitui": origem, "emitida_por": self.nome, "modalidade": modalidade}
        if modalidade == "business":
            # Os dados da empresa ficam numa pasta só dela (modCaminhos.definir_organizacao).
            lic["organizacao"] = (organizacao or unidade or "").strip() or "empresa"
        chave = L.para_chave(L.empacotar(lic, self.assinador))
        self._registrar(operacao, lic["licenca_id"], instalacao,
                        f"{L.MODALIDADES[modalidade]}; unidade {unidade}; até {lic['valida_ate']}"
                        + (f"; organização {lic['organizacao']}" if lic.get("organizacao") else "")
                        + (f"; substitui {origem}" if origem else ""))
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
        certs.append({"thumbprint": thumbprint, "titular": titular, "papel": papel, "desde": _agora()})
        doc["certificados"] = certs
        doc["revogados"] = [t for t in doc.get("revogados", []) if t != thumbprint]
        self._publicar("credenciamentos", doc)
        self._registrar("credenciar", "", instalacao, f"{thumbprint[:8]}… papel {papel}")

    def credenciar_pedido(self, pedido, papel="usuario"):
        p = L.ler_pedido(pedido)
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
            admins[adicionar.upper()] = nome or adicionar[:8]
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
    pub = L.Publicacao(pasta_cache=Path(pasta) / "_nao_usado", pasta_pacote=pasta, online=False)
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
    a.add_argument("--adicionar")
    a.add_argument("--nome", default="")
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
            adm.administradores(args.adicionar, args.nome, args.remover)
            print("Lista de administradores atualizada.")
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
    git = (raiz / ".git").exists()
    comando = f'git add licencas ; git commit -m "Licenças: {cmd}" ; git push'
    if cmd in MUDAM_LISTAS:
        inicio = "PUBLIQUE para valer nas outras instalações"
    else:
        inicio = ("A licença já pode ser enviada ao usuário. Para guardar o registro desta operação no GitHub "
                  "(recomendado)")
    if git:
        return f"{inicio}: {comando}"
    return (f"{inicio}: esta pasta não é um clone do Git (veio de um ZIP). Copie a pasta licencas para um clone "
            f"do repositório e rode lá: {comando}")


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
