# ==============================================================================
#  S-Cyber - Primeiros passos
# ------------------------------------------------------------------------------
#  Arquivo     : modPrimeirosPassos.py
#  Descrição   : Lista de primeiros passos na tela principal (Fase 6): mostra o que já
#                foi feito e leva a pessoa ao próximo passo com um clique
#  Autores     : Gabriel Silveira Lima
#  Licença     : Proprietária - todos os direitos reservados (ver LICENSE)
# ==============================================================================
"""Primeiros passos do S-Cyber, do aceite dos termos à primeira correção comprovada.

A situação de cada passo vem do que está gravado (aceite, licença, certificado em uso e o
banco NIST). O banco é lido SOMENTE com contagens em modo leitura (sem a chave): nenhum
texto cifrado é aberto aqui. A instalação e a ativação já passaram quando esta tela aparece.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path


def _contagens(banco):
    """(diagnósticos, correções comprovadas) do banco NIST, ou (0, 0) se ele ainda não existe."""
    if not banco or not Path(banco).is_file():
        return 0, 0
    try:
        con = sqlite3.connect(Path(banco).resolve().as_uri() + "?mode=ro", uri=True)   # file:///C:/...
        try:
            diagnosticos = con.execute("SELECT COUNT(*) FROM collections").fetchone()[0]
            try:
                comprovadas = con.execute("SELECT COUNT(*) FROM achados WHERE state='Encerrado'").fetchone()[0]
            except sqlite3.Error:
                comprovadas = 0
            return diagnosticos, comprovadas
        finally:
            con.close()
    except sqlite3.Error:
        return 0, 0


def _tem_backup(banco):
    if not banco:
        return False
    pasta = Path(banco).parent / "backups"
    return pasta.is_dir() and any(pasta.glob("*.db"))


def passos(termos_ok, licenca, cert_thumb, banco=None):
    """[{'chave', 'titulo', 'feito', 'detalhe'}] na ordem em que devem ser feitos."""
    diagnosticos, comprovadas = _contagens(banco)
    licenca = licenca or {}
    return [
        {"chave": "termos", "titulo": "Aceitar os Termos de Uso e a Política de Privacidade",
         "feito": bool(termos_ok), "detalhe": "Ajuda > Termos de Uso e Privacidade"},
        {"chave": "licenca", "titulo": "Ativar a licença",
         "feito": bool(licenca.get("licenca_id")),
         "detalhe": (f"válida até {str(licenca.get('valida_ate', ''))[:10]}" if licenca.get("valida_ate")
                     else "peça a licença ao suporte")},
        {"chave": "certificado", "titulo": "Entrar com o certificado digital",
         "feito": bool(cert_thumb), "detalhe": "desafio e resposta, sem senha de fábrica"},
        {"chave": "diagnostico", "titulo": "Fazer o primeiro diagnóstico (um clique)",
         "feito": diagnosticos > 0,
         "detalhe": f"{diagnosticos} diagnóstico(s) registrado(s)" if diagnosticos else "somente leitura"},
        {"chave": "correcao", "titulo": "Corrigir um problema e comprovar com nova verificação",
         "feito": comprovadas > 0,
         "detalhe": (f"{comprovadas} correção(ões) comprovada(s)" if comprovadas
                     else "registre a correção no achado e rode o diagnóstico de novo")},
        {"chave": "backup", "titulo": "Ter uma cópia de segurança dos dados",
         "feito": _tem_backup(banco),
         "detalhe": "cópia automática diária do banco NIST; também em NIST > Relatório > Backup"},
    ]


def proximo(lista):
    """O primeiro passo ainda não feito, ou None quando todos estão feitos."""
    return next((p for p in lista if not p["feito"]), None)


ACAO_TEXTO = {"diagnostico": "Fazer o diagnóstico", "correcao": "Ver os problemas",
              "backup": "Abrir o backup", "termos": "Ler os termos"}


def criar_cartao(parent, obter_passos, acoes):
    """Cartão da tela principal. obter_passos() -> passos(...); acoes[chave]() faz o passo.
    Devolve o Frame, com o método .atualizar()."""
    import tkinter as tk

    cartao = tk.Frame(parent, bg="#f4f7fb", highlightthickness=1, highlightbackground="#c9d6e3",
                      padx=14, pady=10)
    tk.Label(cartao, text="Primeiros passos", bg="#f4f7fb", fg="#14324f",
             font=("Segoe UI", 11, "bold")).grid(row=0, column=0, columnspan=3, sticky="w")
    linhas = tk.Frame(cartao, bg="#f4f7fb")
    linhas.grid(row=1, column=0, columnspan=3, sticky="w", pady=(4, 6))
    botao = tk.Button(cartao, text="", bg="#1f6fb2", fg="white", activebackground="#185a91",
                      activeforeground="white", relief="flat", padx=12, pady=3, cursor="hand2")
    botao.grid(row=2, column=0, sticky="w")
    fechar = tk.Label(cartao, text="Esconder", bg="#f4f7fb", fg="#5a6b7b", cursor="hand2",
                      font=("Segoe UI", 9, "underline"))
    fechar.grid(row=2, column=2, sticky="e")
    cartao.columnconfigure(1, weight=1)

    def atualizar():
        for filho in linhas.winfo_children():
            filho.destroy()
        lista = obter_passos()
        for i, p in enumerate(lista):
            marca, cor = ("✔", "#2e7d32") if p["feito"] else ("○", "#5a6b7b")
            tk.Label(linhas, text=marca, bg="#f4f7fb", fg=cor, font=("Segoe UI", 10, "bold")
                     ).grid(row=i, column=0, sticky="w", padx=(0, 6))
            tk.Label(linhas, text=p["titulo"], bg="#f4f7fb", fg="#14324f" if not p["feito"] else "#5a6b7b",
                     font=("Segoe UI", 10)).grid(row=i, column=1, sticky="w")
            tk.Label(linhas, text=p["detalhe"], bg="#f4f7fb", fg="#7a8a99", font=("Segoe UI", 9)
                     ).grid(row=i, column=2, sticky="w", padx=(10, 0))
        seguinte = proximo(lista)
        if seguinte and seguinte["chave"] in acoes:
            botao.configure(text=ACAO_TEXTO.get(seguinte["chave"], "Fazer agora"),
                            command=lambda c=seguinte["chave"]: (acoes[c](), cartao.after(1500, atualizar)))
            botao.grid()
        elif seguinte is None:
            botao.configure(text="Tudo pronto: ver a evolução", command=acoes.get("evolucao", lambda: None))
            botao.grid()
        else:
            botao.grid_remove()
        return lista

    cartao.atualizar = atualizar
    cartao.fechar = fechar
    return cartao
