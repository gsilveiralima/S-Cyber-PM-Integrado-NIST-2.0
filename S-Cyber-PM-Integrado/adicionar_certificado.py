# ==============================================================================
#  S-Cyber PM - Cryptography and Digital Certificate Framework
# ------------------------------------------------------------------------------
#  Arquivo     : adicionar_certificado.py
#  Descrição   : Acrescenta um certificado à lista CERTIFICADOS_AUTORIZADOS
#  Revisões    : 2026-11-22  Criação (instalação validada no Windows 11)
# ==============================================================================
"""
Acrescenta o thumbprint de um certificado à lista CERTIFICADOS_AUTORIZADOS do
appSCyberPM.py, sem precisar abrir o arquivo no editor.

    .venv\\Scripts\\python.exe adicionar_certificado.py B330B18E7E10C2F4F9182E911516A13DA0591CC9 "SGT Fulano"

O thumbprint é conferido (40 caracteres hexadecimais) e não é repetido se já
estiver na lista. O certificado precisa estar no repositório Pessoal do usuário,
com a chave privada: confira depois com verificar_certificados.ps1.
"""
import re
import sys
from pathlib import Path

APP = Path(__file__).resolve().parent / "appSCyberPM.py"
LISTA = re.compile(r"(CERTIFICADOS_AUTORIZADOS\s*=\s*\[)(.*?)(\n\])", re.S)


def adicionar(thumbprint, comentario="", caminho=APP):
    # Aceita só dígitos hexadecimais, espaços e os caracteres invisíveis que vêm
    # junto ao copiar do certmgr (marcas de direção e BOM); qualquer outro é erro.
    tp = re.sub(r"[\s\u200e\u200f\ufeff]", "", thumbprint).upper()
    if not re.fullmatch(r"[0-9A-F]{40}", tp):
        raise ValueError("Thumbprint inválido: precisa ter 40 caracteres hexadecimais.")
    texto = caminho.read_text(encoding="utf-8")
    achado = LISTA.search(texto)
    if not achado:
        raise ValueError("Lista CERTIFICADOS_AUTORIZADOS não encontrada no appSCyberPM.py.")
    if tp in achado.group(2).upper():
        return False
    comentario = re.sub(r"[\r\n]", " ", comentario).strip()
    linha = f'\n    "{tp}",' + (f"   # {comentario}" if comentario else "")
    novo = texto[:achado.end(2)] + linha + texto[achado.end(2):]
    caminho.write_text(novo, encoding="utf-8", newline="")
    return True


def main(args):
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return 1
    try:
        incluido = adicionar(args[0], " ".join(args[1:]))
    except (ValueError, OSError) as erro:
        print(f"ERRO: {erro}")
        return 2
    print("Certificado incluído na lista." if incluido else "Esse certificado já estava na lista.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
