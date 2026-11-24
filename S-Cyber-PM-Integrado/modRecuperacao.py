"""Recuperação dos dados quando a LICENÇA não vale (vencida, revogada, lista vencida ou
instalação transferida).

A licença controla o USO do programa, nunca a posse dos dados do titular. Sem licença
válida, o titular continua podendo, depois de provar quem é (certificado validado +
senha de acesso), exportar tudo o que é dele:
  * cópia de segurança do banco NIST (continua cifrada com o certificado);
  * planilhas CSV de cada registro (riscos, incidentes, evidências, achados, auditoria…);
  * MANIFESTO.txt com o SHA-256 de cada arquivo.
A exportação fica na trilha de auditoria. Nada é alterado nem apagado.
"""
from __future__ import annotations

import hashlib
from datetime import datetime
from pathlib import Path

RECUPERAVEIS = ("expirada", "revogada", "lista_vencida", "sem_lista", "outra_instalacao")


def disponivel(codigo, pasta_dados=None):
    """True se faz sentido oferecer a recuperação: a licença falhou por um motivo
    recuperável e existe um perfil com dados."""
    if codigo not in RECUPERAVEIS:
        return False
    from modPerfil import pasta_dados as _pasta
    pasta = Path(pasta_dados or _pasta())
    return (pasta / "scyber_pm.opcoes").is_file() or (pasta / "nist" / "nist.db").is_file()


def exportar(destino, thumb, senha, motivo, actor="", db_path=None):
    """Confere a senha do titular (com as opções abertas pela chave do certificado) e exporta.
    Devolve a pasta criada. Levanta PermissionError se a senha não confere."""
    import formOpcoes
    from nist_intelligence import core
    from nist_intelligence.crypto import derive_key
    formOpcoes.iniciar(thumb)
    if not formOpcoes.senhas_criadas() or not formOpcoes.conferir_login(formOpcoes.usuario(), senha):
        raise PermissionError("Senha de acesso incorreta: a recuperação exige a senha do titular.")
    pasta = Path(destino) / f"recuperacao_scyber_{datetime.now():%Y%m%d_%H%M%S}"
    pasta.mkdir(parents=True)
    db_path = Path(db_path or core.DB)
    linhas = [f"S-Cyber PM — recuperação de dados ({datetime.now():%d/%m/%Y %H:%M})",
              f"Motivo: licença {motivo}. Titular: {formOpcoes.usuario()} (certificado {thumb[:8]}…)", ""]
    if db_path.is_file():
        db = core.connect(db_path, derive_key(formOpcoes.chave_do_arquivo()))
        try:
            db.definir_sessao(actor or f"{formOpcoes.usuario()} cert {thumb[:8]}", "usuario")
            core.backup(db, pasta / "nist_backup_cifrado.db")
            for tipo in ("plano", *core.EXPORTS):
                try:
                    core.export_csv(db, tipo, pasta / f"{tipo}.csv")
                except Exception as exc:  # noqa: BLE001 — tabela de versão antiga: registra e segue
                    linhas.append(f"(não exportado: {tipo} — {exc})")
            core.audit(db, "Recuperação", "Exportar com licença inválida", "",
                       f"licença {motivo}; pasta {pasta.name}")
            db.commit()
        finally:
            db.close()
    linhas.append("Arquivos (SHA-256):")
    for arq in sorted(pasta.iterdir()):
        linhas.append(f"  {hashlib.sha256(arq.read_bytes()).hexdigest()}  {arq.name}")
    linhas += ["", "O backup cifrado abre no S-Cyber PM com o MESMO certificado (Relatório > Restaurar backup).",
               "Os CSV estão em claro: guarde-os em local protegido e apague quando não forem mais necessários."]
    (pasta / "MANIFESTO.txt").write_text("\n".join(linhas) + "\n", encoding="utf-8")
    return pasta
