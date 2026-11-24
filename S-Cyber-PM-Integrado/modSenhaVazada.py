"""Pwned Passwords na criação e na troca de senha (formTrocaSenha e Opções).

Só os 5 primeiros caracteres do SHA-1 da senha saem do computador (k-anonimato, com
Add-Padding); a comparação do restante é feita aqui. Senha encontrada em vazamentos é
recusada. Sem internet, o usuário decide se continua (a política de senha forte vale
sempre).
"""
from tkinter import messagebox


def _consulta_padrao():
    from nist_intelligence import fontes
    return lambda s: fontes.senha_vazada(s, lambda url, headers=None: fontes.http_get(url, headers, timeout=8))


def pode_usar(senha, rotulo, janela, consultar=None):
    """Versão que espera a rede na thread da tela (use conferir_e_continuar nas telas)."""
    situacao, vezes = (consultar or _consulta_padrao())(senha)
    return decidir(situacao, vezes, rotulo, janela)


def conferir_e_continuar(janela, pares, continuar, consultar=None, ao_terminar=None):
    """Consulta as senhas [(senha, rótulo)] em SEGUNDO PLANO (até 8 s cada, sem travar a
    tela). Na volta, avisa ou pergunta e chama continuar() só se todas puderem ser usadas.
    ao_terminar() é chamado sempre que a consulta volta (ex.: liberar o botão)."""
    from nist_intelligence import fontes
    from modRecursos import em_segundo_plano
    consultar = consultar or _consulta_padrao()
    pares = [(s, r) for s, r in pares if s]

    def pronto(resultados, erro):
        janela.configure(cursor="")
        if ao_terminar is not None:
            ao_terminar()
        if erro is not None:
            resultados = [(r, fontes.INDISPONIVEL, 0) for _, r in pares]
        for rotulo, situacao, vezes in resultados:
            if not decidir(situacao, vezes, rotulo, janela):
                return
        continuar()

    janela.configure(cursor="watch")
    em_segundo_plano(janela, lambda: [(r, *consultar(s)) for s, r in pares], pronto)


def decidir(situacao, vezes, rotulo, janela):
    from nist_intelligence import fontes
    if situacao == fontes.CORRESPONDENCIA:
        messagebox.showwarning("Senha vazada", f"A {rotulo} aparece {vezes:,} vez(es) em vazamentos públicos "
                               "(Have I Been Pwned / Pwned Passwords). Escolha outra.".replace(",", "."),
                               parent=janela)
        return False
    if situacao == fontes.SEM_CORRESPONDENCIA:
        return True
    return messagebox.askyesno("Pwned Passwords", f"Não foi possível conferir se a {rotulo} já vazou "
                               f"({situacao}). Usar mesmo assim?", parent=janela)
