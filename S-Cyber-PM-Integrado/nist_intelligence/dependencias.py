"""Dependências vulneráveis do próprio S-Cyber (OSV.dev), para o CI e para o desenvolvedor.

    python -m nist_intelligence.dependencias requirements-lock.txt

Lê as versões EXATAS do arquivo de travamento e consulta o OSV.dev pelo mecanismo único de
fontes (fontes.osv_pacotes). Código de saída: 0 sem vulnerabilidade conhecida, 1 com
vulnerabilidade, 2 quando a consulta não pôde ser feita (nunca conta como aprovado).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from . import fontes


def relatorio(caminho, post=None, baixar=None):
    pacotes = fontes.pacotes_de_requirements(Path(caminho).read_text(encoding='utf-8'))
    r = fontes.osv_pacotes(pacotes, post=post, baixar=baixar)
    linhas = [f'OSV.dev — {len(pacotes)} pacotes de {Path(caminho).name}, consultado em {r.consultado_em}: '
              f'{r.situacao}']
    if r.mensagem:
        linhas.append(r.mensagem)
    for i in r.itens:
        apelidos = f" ({', '.join(i['apelidos'])})" if i['apelidos'] else ''
        corrige = f"; corrigido em {i['corrigido_em']}" if i['corrigido_em'] else '; sem versão corrigida informada'
        linhas.append(f"- {i['pacote']} {i['versao']}: {i['id']}{apelidos} — {i['resumo']}{corrige}")
    codigo = 0 if r.situacao == fontes.SEM_CORRESPONDENCIA else 1 if r.situacao == fontes.CORRESPONDENCIA else 2
    return codigo, '\n'.join(linhas)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print('Uso: python -m nist_intelligence.dependencias requirements-lock.txt')
        return 2
    codigo, texto = relatorio(argv[0])
    print(texto)
    resumo = os.environ.get('GITHUB_STEP_SUMMARY')
    if resumo:                                  # aparece na página da execução do GitHub Actions
        with open(resumo, 'a', encoding='utf-8') as f:
            f.write('## Dependências (OSV.dev)\n\n```\n' + texto + '\n```\n')
    return codigo


if __name__ == '__main__':
    raise SystemExit(main())
