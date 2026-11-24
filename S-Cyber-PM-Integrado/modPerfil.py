"""Perfil do usuário (%APPDATA%\\SCyberPM): arquivos cifrados com o certificado, troca de
certificado e recuperação.

Os arquivos tratados em conjunto:
  * scyber_pm.opcoes          — opções e senha de acesso (chave = HKDF(assinatura do certificado));
  * nist\\nist.db               — banco do NIST Intelligence (subchave da mesma chave);
  * cópias: nist\\backups\\*.db, *.antigo, *.antes-restauracao-*, arquivo\\**.

Regras:
  * nada é apagado: o que sai de uso vai para arquivo\\<data>_<motivo>\\ com um LEIA-ME;
  * migração só com o certificado antigo ACESSÍVEL (com a chave privada neste usuário):
    cópia → recifra → confere registro a registro → testa a restauração → só então troca;
  * sem a chave antiga não há como ler os dados: o acervo é preservado e um perfil novo
    só é criado por escolha expressa do titular.
"""
from __future__ import annotations

import json
import os
import shutil
from datetime import datetime
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class ErroPerfil(Exception):
    pass


def pasta_dados():
    import modCaminhos                  # fonte única das pastas (S-Cyber 2.0, M5)
    return modCaminhos.pasta_dados(criar=False)


MAGICO_OPCOES = b"SCPMOPT1"      # o mesmo formOpcoes.MAGICO (conferido nos testes)


def _magico():
    return MAGICO_OPCOES


def chave_opcoes(thumb):
    """Chave do arquivo de opções para o certificado (assinatura pelo Windows)."""
    import formOpcoes
    return formOpcoes._derivar_chave(thumb)


def chave_nist(chave_op):
    from nist_intelligence.crypto import derive_key
    return derive_key(chave_op)


# ------------------------------------------------------------------ arquivo de opções
def ler_opcoes(caminho, chave, thumb):
    bruto = Path(caminho).read_bytes()
    magico = _magico()
    if not bruto.startswith(magico) or len(bruto) < len(magico) + 28:
        raise ErroPerfil("O arquivo de opções não está no formato esperado.")
    nonce = bruto[len(magico):len(magico) + 12]
    try:
        texto = AESGCM(chave).decrypt(nonce, bruto[len(magico) + 12:], magico + thumb.encode("ascii"))
    except InvalidTag as exc:
        raise ErroPerfil("Esta chave não abre o arquivo de opções.") from exc
    return json.loads(texto.decode("utf-8"))


def gravar_opcoes(caminho, chave, thumb, dados):
    magico = _magico()
    nonce = os.urandom(12)
    cifrado = AESGCM(chave).encrypt(nonce, json.dumps(dados).encode("utf-8"), magico + thumb.encode("ascii"))
    Path(caminho).write_bytes(magico + nonce + cifrado)


def opcoes_abre(caminho, chave, thumb):
    try:
        ler_opcoes(caminho, chave, thumb)
        return True
    except (ErroPerfil, OSError, ValueError):
        return False


# ------------------------------------------------------------------ inventário
def artefatos(pasta=None):
    """Arquivos cifrados do perfil: [(tipo, caminho)], o ativo primeiro."""
    pasta = Path(pasta or pasta_dados())
    out = []
    if (pasta / "scyber_pm.opcoes").is_file():
        out.append(("opcoes", pasta / "scyber_pm.opcoes"))
    for p in sorted(pasta.glob("scyber_pm.opcoes?*")):
        out.append(("opcoes", p))
    nist = pasta / "nist"
    if (nist / "nist.db").is_file():
        out.append(("nist", nist / "nist.db"))
    for padrao in ("nist.db?*", "nist.antes-restauracao-*"):
        out += [("nist", p) for p in sorted(nist.glob(padrao)) if p.is_file()]
    out += [("nist", p) for p in sorted((nist / "backups").glob("*.db"))]
    arq = pasta / "arquivo"
    if arq.is_dir():
        for p in sorted(arq.rglob("*")):
            if p.is_file() and (p.name.endswith(".db") or p.name.startswith("scyber_pm.opcoes")):
                out.append(("nist" if p.name.endswith(".db") else "opcoes", p))
    return out


def quem_abre(tipo, caminho, chaves):
    """chaves: {thumb: chave_opcoes}. Devolve o thumb do certificado que abre o arquivo,
    'sem_cifra' (banco antigo em claro) ou None."""
    from nist_intelligence import core
    for thumb, chave in chaves.items():
        if chave is None:
            continue
        if tipo == "opcoes" and opcoes_abre(caminho, chave, thumb):
            return thumb
        if tipo == "nist":
            st = core.key_status(caminho, chave_nist(chave))
            if st == "abre":
                return thumb
            if st == "sem_cifra":
                return "sem_cifra"
    return None


def chaves_disponiveis(certificados, derivar=chave_opcoes):
    """{thumb: chave} dos certificados COM chave privada (os outros não abrem nada).
    certificados: [{'thumb', 'chave_privada', ...}] (modDiagnostico.listar_certificados)."""
    out = {}
    for c in certificados:
        if not c.get("chave_privada"):
            continue
        try:
            out[c["thumb"]] = derivar(c["thumb"])
        except Exception:
            out[c["thumb"]] = None          # chave protegida/cancelada pelo usuário
    return out


def analisar(thumb_atual, certificados, pasta=None, derivar=chave_opcoes):
    """Inventário do perfil: [{tipo, caminho, tamanho, modificado, abre_com, situacao}].
    situacao: 'atual' | 'outro_certificado' | 'sem_chave' | 'sem_cifra'."""
    chaves = chaves_disponiveis(certificados, derivar)
    ordem = {thumb_atual: chaves.get(thumb_atual)} if thumb_atual in chaves else {}
    ordem.update({t: k for t, k in chaves.items() if t != thumb_atual})
    out = []
    for tipo, caminho in artefatos(pasta):
        quem = quem_abre(tipo, caminho, ordem)
        st = caminho.stat()
        situacao = ("atual" if quem == thumb_atual else "sem_cifra" if quem == "sem_cifra"
                    else "outro_certificado" if quem else "sem_chave")
        out.append({"tipo": tipo, "caminho": str(caminho), "tamanho": st.st_size,
                    "modificado": datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
                    "abre_com": quem if quem not in (None, "sem_cifra") else None, "situacao": situacao})
    return out, chaves


# ------------------------------------------------------------------ guardar sem apagar
def arquivar(itens, motivo, pasta=None):
    """Move os arquivos para arquivo\\<data>_<motivo>\\, com um LEIA-ME. Devolve a pasta."""
    pasta = Path(pasta or pasta_dados())
    destino = pasta / "arquivo" / f"{datetime.now():%Y%m%d-%H%M%S}_{motivo}"
    destino.mkdir(parents=True, exist_ok=True)
    linhas = [f"Arquivos guardados pelo S-Cyber PM em {datetime.now():%d/%m/%Y %H:%M} ({motivo}).",
              "Nada foi apagado. Para voltar a usar, feche o S-Cyber PM e mova o arquivo de volta",
              "para a pasta original (as opções em SCyberPM, o banco em SCyberPM\\nist).", ""]
    for item in itens:
        item = Path(item)
        if item.is_file():
            alvo = destino / item.name
            shutil.move(str(item), alvo)
            linhas.append(f"{item}  ->  {alvo.name}")
    (destino / "LEIA-ME.txt").write_text("\n".join(linhas) + "\n", encoding="utf-8")
    return destino


# ------------------------------------------------------------------ migração
def migrar(thumb_antigo, chave_antiga, thumb_novo, chave_nova, pasta=None, origem_nist=None, actor=""):
    """Leva opções e banco NIST do certificado antigo para o novo.

    origem_nist: banco a migrar (padrão: o nist.db ativo; pode ser uma cópia, ex.
    nist.db.antigo, quando o ativo está vazio). Devolve o relatório (dict)."""
    from nist_intelligence import core
    pasta = Path(pasta or pasta_dados())
    opcoes = pasta / "scyber_pm.opcoes"
    nist_ativo = pasta / "nist" / "nist.db"
    origem_nist = Path(origem_nist) if origem_nist else nist_ativo
    preparo = pasta / "migracao" / f"{datetime.now():%Y%m%d-%H%M%S}"
    preparo.mkdir(parents=True, exist_ok=True)
    relatorio = {"de": thumb_antigo, "para": thumb_novo, "quando": datetime.now().isoformat(timespec="seconds"),
                 "opcoes": None, "nist": None, "restauracao": None, "arquivo": None}

    # 1. Opções: decifra com a chave antiga e grava cifrado com a nova (na pasta de preparo).
    nova_opcoes = None
    if opcoes.is_file() and opcoes_abre(opcoes, chave_antiga, thumb_antigo):
        dados = ler_opcoes(opcoes, chave_antiga, thumb_antigo)
        nova_opcoes = preparo / "scyber_pm.opcoes"
        gravar_opcoes(nova_opcoes, chave_nova, thumb_novo, dados)
        if ler_opcoes(nova_opcoes, chave_nova, thumb_novo) != dados:
            raise ErroPerfil("A cópia das opções não confere com o original.")
        relatorio["opcoes"] = "migradas (usuário, senha e preferências preservados)"

    # 2. Banco NIST: recifra numa cópia e confere registro a registro e as cadeias.
    novo_nist = None
    if origem_nist.is_file():
        novo_nist = preparo / "nist.db"
        contagem = core.rekey(origem_nist, chave_nist(chave_antiga), chave_nist(chave_nova), novo_nist)
        relatorio["nist"] = {"origem": str(origem_nist), "registros": contagem}
        # 3. Restauração de teste: o banco migrado precisa restaurar e abrir com a chave nova.
        teste = preparo / "teste_restauracao.db"
        core.restore(novo_nist, teste, chave_nist(chave_nova))
        core.compare_databases(novo_nist, chave_nist(chave_nova), teste, chave_nist(chave_nova),
                               appended=("audit_log",))
        relatorio["restauracao"] = "restauração de teste conferida"
        for extra in preparo.glob("teste_restauracao*"):
            extra.unlink()
    if nova_opcoes is None and novo_nist is None:
        raise ErroPerfil("O certificado antigo não abre nenhum dos arquivos do perfil.")

    # 4. Só agora mexe nos arquivos ativos: o que estava em uso vai para o arquivo.
    sair = [p for p in (opcoes if nova_opcoes else None, nist_ativo if novo_nist else None) if p and p.exists()]
    if origem_nist != nist_ativo and novo_nist:
        sair.append(origem_nist)
    relatorio["arquivo"] = str(arquivar(sair, f"migracao_{thumb_antigo[:8]}_para_{thumb_novo[:8]}", pasta))
    if nova_opcoes:
        shutil.move(str(nova_opcoes), opcoes)
    if novo_nist:
        nist_ativo.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(novo_nist), nist_ativo)
        db = core.connect(nist_ativo, chave_nist(chave_nova))
        try:
            db.actor = actor or "migração de certificado"
            core.audit(db, "Perfil", "Migrar certificado", "",
                       f"{thumb_antigo[:8]}… → {thumb_novo[:8]}…; arquivo {Path(relatorio['arquivo']).name}")
            db.commit()
        finally:
            db.close()
    (Path(relatorio["arquivo"]) / "relatorio_migracao.json").write_text(
        json.dumps(relatorio, ensure_ascii=False, indent=2), encoding="utf-8")
    shutil.rmtree(preparo, ignore_errors=True)
    return relatorio


def novo_perfil(confirmacao, pasta=None):
    """Sem a chave antiga: guarda o acervo e libera um perfil novo. Exige que o titular
    digite exatamente NOVO PERFIL. Devolve a pasta do arquivo."""
    if confirmacao.strip().upper() != "NOVO PERFIL":
        raise ErroPerfil('Para criar um perfil novo, digite exatamente: NOVO PERFIL')
    pasta = Path(pasta or pasta_dados())
    itens = [pasta / "scyber_pm.opcoes", pasta / "nist" / "nist.db"]
    return arquivar([i for i in itens if i.exists()], "perfil_anterior_sem_chave", pasta)
