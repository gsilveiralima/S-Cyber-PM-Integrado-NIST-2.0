"""Pwned Passwords na criação e na troca de senha (formTrocaSenha e Opções).

Só os 5 primeiros caracteres do SHA-1 da senha saem do computador (k-anonimato, com
Add-Padding); a comparação do restante é feita aqui. Senha encontrada em vazamentos é
recusada. Sem internet, o usuário decide se continua (a política de senha forte vale
sempre).
"""
from tkinter import messagebox


def pode_usar(senha, rotulo, janela, consultar=None):
    from nist_intelligence import fontes
    consultar = consultar or (lambda s: fontes.senha_vazada(
        s, lambda url, headers=None: fontes.http_get(url, headers, timeout=8)))
    situacao, vezes = consultar(senha)
    if situacao == fontes.CORRESPONDENCIA:
        messagebox.showwarning("Senha vazada", f"A {rotulo} aparece {vezes:,} vez(es) em vazamentos públicos "
                               "(Have I Been Pwned / Pwned Passwords). Escolha outra.".replace(",", "."),
                               parent=janela)
        return False
    if situacao == fontes.SEM_CORRESPONDENCIA:
        return True
    return messagebox.askyesno("Pwned Passwords", f"Não foi possível conferir se a {rotulo} já vazou "
                               f"({situacao}). Usar mesmo assim?", parent=janela)
