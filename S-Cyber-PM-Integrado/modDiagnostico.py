"""Diagnóstico da abertura do S-Cyber PM — somente leitura.

Mostra a versão em execução, o caminho do programa, a pasta de dados, a conta do
Windows, os certificados de Cert:\\CurrentUser\\My (com a situação de cada um), a
ativação, os arquivos cifrados do perfil e qual certificado abre cada um, a etapa que
falhou e a PRÓXIMA AÇÃO.

Pela linha de comando (não precisa da interface):
    SCyberPM.exe --diagnostico            (grava no Desktop e abre no Bloco de Notas)
    python appSCyberPM.py --diagnostico C:\\caminho\\diagnostico.txt
"""
from __future__ import annotations

import json
import os
import socket
import sys
from datetime import datetime
from pathlib import Path

ETAPAS = {
    "licenca": "Ativação da instalação",
    "certificado": "Certificado digital",
    "opcoes": "Opções do aplicativo (arquivo cifrado)",
    "nist": "Banco do NIST Intelligence (arquivo cifrado)",
}

_PS_CERTS = r"""
$ErrorActionPreference = 'Stop'
@(Get-ChildItem -Path 'Cert:\CurrentUser\My' | ForEach-Object {
  $alg = ''
  try { $alg = $_.PublicKey.Oid.FriendlyName } catch {}
  [ordered]@{ thumb=$_.Thumbprint; titular=$_.Subject; emissor=$_.Issuer; chave_privada=[bool]$_.HasPrivateKey;
              inicio=$_.NotBefore.ToString('s'); fim=$_.NotAfter.ToString('s'); algoritmo=$alg }
}) | ConvertTo-Json -Compress -Depth 3
"""


def _powershell(script, timeout=25, variaveis=None):
    """(saída, erro) do script; falha de execução vem como ("", motivo)."""
    import modPowerShell
    try:
        r = modPowerShell.executar(script, variaveis=variaveis, timeout=timeout, codificado=True)
    except modPowerShell.ErroPowerShell as exc:
        return "", str(exc)
    return r.saida.strip(), r.erro.strip()


def listar_certificados():
    """[{thumb, titular, emissor, chave_privada, inicio, fim, algoritmo}] do usuário atual."""
    if sys.platform != "win32":
        return []
    saida, erro = _powershell(_PS_CERTS)
    if not saida:
        if erro:
            raise RuntimeError(erro)
        return []
    dados = json.loads(saida.splitlines()[-1])
    if isinstance(dados, dict):
        dados = [dados]
    for c in dados:
        c["thumb"] = c["thumb"].upper()
    return dados


def classificar(cert, autorizados, agora=None, credenciados=None):
    """'pronto' | 'sem_chave' | 'vencido' | 'nao_autorizado' | 'nao_rsa'."""
    agora = agora or datetime.now()
    autorizado = cert["thumb"] in set(autorizados) | set(credenciados or ())
    if not autorizado:
        return "nao_autorizado"
    if not cert.get("chave_privada"):
        return "sem_chave"
    try:
        if not (datetime.fromisoformat(cert["inicio"]) <= agora <= datetime.fromisoformat(cert["fim"])):
            return "vencido"
    except (KeyError, ValueError):
        return "vencido"
    if cert.get("algoritmo") and cert["algoritmo"].upper() != "RSA":
        return "nao_rsa"
    return "pronto"


SITUACAO = {
    "pronto": "PRONTO PARA USO",
    "sem_chave": "autorizado, mas SEM a chave privada (só a parte pública foi importada)",
    "vencido": "autorizado, mas fora da validade",
    "nao_autorizado": "não está na lista de autorizados nem credenciado",
    "nao_rsa": "autorizado, mas a chave não é RSA",
}


def resumo_certificados(certs, autorizados, credenciados=None, agora=None):
    """(situação geral, [(cert, classificação)]) — geral: 'pronto', 'ausente', 'sem_chave',
    'vencido' ou 'nao_autorizado'."""
    itens = [(c, classificar(c, autorizados, agora, credenciados)) for c in certs]
    estados = {e for _, e in itens}
    for geral in ("pronto", "sem_chave", "vencido", "nao_rsa"):
        if geral in estados:
            return geral, itens
    return ("nao_autorizado" if certs else "ausente"), itens


PROXIMA_ACAO = {
    "ausente": "Nenhum certificado nesta conta do Windows. Use 'Criar meu certificado' na tela de abertura e "
               "envie o pedido de credenciamento ao administrador (SGT Gabriel ou MAJ Leonídio).",
    "nao_autorizado": "Há certificados nesta conta, mas nenhum autorizado. Envie o pedido de credenciamento do seu "
                      "certificado ao administrador e, depois do aviso, clique em 'Verificar novamente'.",
    "sem_chave": "O certificado autorizado está sem a chave privada (foi importado só o .cer). A chave não sai do "
                 "computador onde foi criada: crie um certificado nesta conta e peça o credenciamento.",
    "vencido": "O certificado autorizado venceu. Crie um novo e peça o credenciamento; seus dados são migrados "
               "pelo assistente de perfil enquanto o certificado antigo continuar instalado.",
    "nao_rsa": "Use um certificado RSA (o S-Cyber PM assina com RSA/SHA-256).",
}


def registrar_execucao(programa, versao, pasta=None):
    """Grava quem está usando o perfil. Devolve um aviso se OUTRA cópia do programa o usou."""
    from modPerfil import pasta_dados
    pasta = Path(pasta or pasta_dados())
    arq = pasta / "perfil.json"
    try:
        anterior = json.loads(arq.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        anterior = {}
    aviso = None
    prog_ant = anterior.get("programa")
    if prog_ant and Path(prog_ant) != Path(programa) and Path(prog_ant).exists():
        aviso = (f"Este perfil também foi usado pela cópia em {prog_ant} (versão {anterior.get('versao', '?')}, "
                 f"{anterior.get('quando', '?')[:16].replace('T', ' ')}). Mantenha uma só cópia do programa: "
                 "listas de certificados e versões diferentes causam erros na abertura.")
    try:
        pasta.mkdir(parents=True, exist_ok=True)
        arq.write_text(json.dumps({"programa": str(programa), "versao": versao,
                                   "quando": datetime.now().isoformat(timespec="seconds"),
                                   "conta": os.environ.get("USERNAME") or os.environ.get("USER") or ""},
                                  indent=2), encoding="utf-8")
    except OSError:
        pass
    return aviso


def relatorio(versao, programa, autorizados, etapa=None, erro=None, thumb_atual=None, publicacao=None,
              certificados=None, analisar_perfil=True, derivar=None):
    """Texto do diagnóstico. Nunca levanta exceção: cada parte registra a própria falha."""
    from modPerfil import pasta_dados
    try:                                           # Business: a pasta de dados é a da empresa
        import modCaminhos
        import modLicenca
        modCaminhos.definir_organizacao(modLicenca.organizacao_da_instalacao(publicacao=publicacao))
    except Exception:  # noqa: BLE001 — sem licença legível, fica a pasta padrão
        pass
    linhas = [f"S-Cyber PM — diagnóstico de abertura ({datetime.now():%d/%m/%Y %H:%M:%S})", "=" * 72,
              f"Versão em execução : {versao}", f"Programa           : {programa}",
              f"Pasta de dados     : {pasta_dados()}",
              f"Conta do Windows   : {os.environ.get('USERDOMAIN', '')}\\{os.environ.get('USERNAME', '')}",
              f"Computador         : {socket.gethostname()}", ""]
    if etapa:
        linhas += [f"ETAPA QUE FALHOU   : {ETAPAS.get(etapa, etapa)}", f"Mensagem           : {erro}", ""]

    # Ativação
    import modLicenca as L
    ativa = None                                   # None = não deu para verificar
    aviso_listas = ""
    try:
        inst = L.instalacao()
        publicacao = publicacao or L.Publicacao()
        ok, lic, exc = L.estado(publicacao=publicacao)
        ativa = bool(ok)
        linhas.append(f"Instalação         : {inst['id']} (máquina {inst['maquina'][:12]}…)")
        linhas.append("Ativação           : " + (f"ATIVA — licença {lic['licenca_id']}, válida até {lic['valida_ate']}"
                                                if ok else f"NÃO ATIVA — {exc}"))
        linhas.append("Listas publicadas  : " + (", ".join(f"{k}={v}" for k, v in publicacao.origem.items())
                                                 or "nenhuma encontrada")
                      + (f" (rede: {publicacao.falha_rede})" if publicacao.falha_rede else ""))
        validades = [f"{n} até {a} ({d} dia(s))" if d is not None else f"{n}: ausente"
                     for n, a, d in L.situacao_listas(publicacao)]
        linhas.append("Validade das listas: " + "; ".join(validades))
        aviso_listas = L.aviso_listas(publicacao)
        if aviso_listas:
            linhas.append(f"AVISO              : {aviso_listas}")
        credenciados = L.credenciados(publicacao)
    except Exception as e:  # noqa: BLE001
        linhas.append(f"Ativação           : não foi possível verificar ({e})")
        credenciados = {}
        aviso_listas = ""
    linhas.append("")

    # Certificados
    geral = "ausente"
    try:
        certs = certificados if certificados is not None else listar_certificados()
        geral, itens = resumo_certificados(certs, autorizados, credenciados)
        linhas.append(f"Certificados em Cert:\\CurrentUser\\My: {len(certs)} — situação geral: {geral.upper()}")
        for c, est in itens:
            linhas.append(f"  {c['thumb']}  {SITUACAO[est]}")
            linhas.append(f"      {c.get('titular', '')}  |  chave privada: {'sim' if c.get('chave_privada') else 'NÃO'}"
                          f"  |  {c.get('inicio', '')[:10]} a {c.get('fim', '')[:10]}")
    except Exception as e:  # noqa: BLE001
        certs = []
        linhas.append(f"Certificados: não foi possível listar ({e})")
    if thumb_atual:
        linhas.append(f"Certificado aceito nesta abertura: {thumb_atual}")
    linhas.append("")

    # Perfil
    if analisar_perfil:
        try:
            import modPerfil
            kwargs = {"derivar": derivar} if derivar else {}
            inventario, _ = modPerfil.analisar(thumb_atual, certs, **kwargs)
            linhas.append(f"Arquivos cifrados do perfil: {len(inventario)}")
            for a in inventario:
                quem = {"atual": "abre com o certificado ATUAL", "sem_cifra": "banco antigo sem cifra",
                        "outro_certificado": f"abre com OUTRO certificado acessível ({(a['abre_com'] or '')[:8]}…)",
                        "sem_chave": "nenhum certificado desta conta abre"}[a["situacao"]]
                linhas.append(f"  {a['caminho']}  ({a['tamanho']} bytes, {a['modificado'][:16].replace('T', ' ')})"
                              f" — {quem}")
        except Exception as e:  # noqa: BLE001
            linhas.append(f"Arquivos do perfil: não foi possível analisar ({e})")
        linhas.append("")

    # Próxima ação
    if etapa == "licenca":
        acao = ("Envie o PEDIDO DE ATIVAÇÃO (tela de ativação > Copiar pedido) ao administrador e cole a chave "
                "recebida. Se a lista de revogações venceu ou não foi encontrada, conecte à internet.")
    elif etapa == "certificado":
        acao = PROXIMA_ACAO.get(geral, "Confira os certificados acima.")
    elif etapa in ("opcoes", "nist"):
        acao = ("Abra o ASSISTENTE DE PERFIL: se um certificado acessível abre os arquivos, ele migra para o "
                "certificado atual (cópia, conferência e restauração de teste antes de trocar). Sem a chave "
                "antiga, os arquivos são guardados e um perfil novo só é criado se você escolher.")
    elif geral != "pronto":
        acao = PROXIMA_ACAO.get(geral, "Confira os certificados acima.")
    elif ativa is False:
        acao = ("Ative esta instalação: abra o S-Cyber PM, use Copiar pedido na tela de ativação, envie o "
                "pedido ao administrador e cole a chave recebida.")
    elif ativa is None:
        acao = "Não foi possível verificar a ativação (veja a mensagem acima); repita o diagnóstico."
    elif aviso_listas:
        acao = "Instalação ativa e certificado pronto, mas: " + aviso_listas
    else:
        acao = "Nenhuma falha encontrada: instalação ativa e certificado pronto."
    linhas += ["PRÓXIMA AÇÃO:", f"  {acao}"]
    return "\n".join(linhas)


def salvar(texto, destino=None):
    if destino is None:
        desk = Path(os.environ.get("USERPROFILE") or Path.home()) / "Desktop"
        destino = (desk if desk.is_dir() else Path.home()) / f"diagnostico_scyber_{datetime.now():%Y%m%d_%H%M%S}.txt"
    Path(destino).write_text(texto, encoding="utf-8")
    return Path(destino)


_PS_CRIAR = r"""
$ErrorActionPreference = 'Stop'
$c = New-SelfSignedCertificate -Subject ('CN=' + $env:SCYBER_CN) -KeyAlgorithm RSA -KeyLength 2048 `
     -KeyExportPolicy NonExportable -KeyUsage DigitalSignature -CertStoreLocation Cert:\CurrentUser\My `
     -NotAfter (Get-Date).AddYears(1)
$c.Thumbprint
"""


def nome_certificado(nome):
    """CN seguro: sem os caracteres que separam campos do nome distinto."""
    limpo = "".join(ch for ch in nome if ch not in ',=+"<>;#\\\r\n').strip()[:60]
    if not limpo:
        raise ValueError("Informe o nome do titular.")
    return f"S-Cyber PM - {limpo}"


def criar_certificado(nome):
    """Cria o certificado do usuário nesta conta do Windows (chave RSA NÃO exportável,
    1 ano). Devolve o thumbprint, para o pedido de credenciamento."""
    if sys.platform != "win32":
        raise RuntimeError("Disponível só no Windows.")
    saida, erro = _powershell(_PS_CRIAR, timeout=60, variaveis={"SCYBER_CN": nome_certificado(nome)})
    thumb = (saida.splitlines() or [""])[-1].strip().upper()
    if len(thumb) != 40:
        raise RuntimeError(erro or "O Windows não criou o certificado.")
    return thumb
