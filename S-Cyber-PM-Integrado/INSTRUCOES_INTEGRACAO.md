# S-Cyber PM 1.5 + NIST Intelligence 1.0.0 — integração

Desenvolvimento conjunto do MAJ Leonídio Alves de Moraes Junior e do SGT Gabriel Silveira Lima,
autorizado para uso nos sistemas da PMGO. A base é o S-Cyber PM 1.4 (`Leonidiojr/S-Cyber-prj`);
esse repositório original não foi modificado.

- Instalação: `../docs/INSTALACAO_WINDOWS.md`.
- Uso do painel NIST: `GUIA_NIST_INTELLIGENCE.md`.

## O que foi integrado ao S-Cyber PM

- Menu e aba da Ribbon **NIST Intelligence**, atalho **Ctrl+Shift+N** e comando do assistente local.
- O painel abre dentro da janela principal (mesmo processo), com as abas: Painel, Avaliação CSF 2.0,
  Plano de ação, Coleta técnica, Riscos, Incidentes, Evidências e custódia, OSINT, Consultas SEI e
  Relatório. **Tela inicial** volta à janela principal.
- Banco em `%APPDATA%\SCyberPM\nist\nist.db`, com os textos **cifrados (AES-256-GCM)** por uma
  chave derivada do certificado do usuário.
- O relatório PDF é assinado e cifrado pelo módulo original `modPDFProtegido`.
- Consulta ao SEI somente leitura, reaproveitando o cliente original `formExploreSEI`.

## Arquivos

| Origem | Arquivos |
|---|---|
| Novos | `nist_intelligence/` (catalog, core, crypto, collector, report, bridge, main), `formNISTIntelligence.py`, `formTrocaSenha.py`, `adicionar_certificado.py`, `verificar_certificados.ps1`, `teste_painel_nist.py`, `tests/`, `requirements-lock.txt` |
| Originais alterados | `appSCyberPM.py` (lista de certificados, AC institucional, painel NIST), `formOpcoes.py` (política de senha), `formLogin.py` (troca obrigatória), `formAbout.py` (versão 1.5), `gerarExe.py` (módulos do painel no `.exe`) |
| Originais sem alteração | os demais `form*.py` e `mod*.py`, imagens e áudio |

O manifesto `../docs/MANIFESTO_ATUALIZACAO_CERTIFICADO.json` registra os SHA-256 da base original
(v0.3.1), para conferência histórica.

## Testes

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

São 42 testes: catálogo CSF, avaliação e plano, riscos, incidentes e prazo da ANPD, custódia,
coleta técnica, relatório, criptografia, SEI, senhas, certificados e inclusão de certificado.
A validação da aplicação no Windows 11 está em `../docs/VALIDACAO_WINDOWS_2026-11-22.md`.

## Limites conhecidos

- A coleta técnica avalia só o computador em que roda, e alguns itens precisam de Administrador.
- O cliente SEI lê as páginas HTML do SEI: uma atualização do SEI pode exigir ajuste. O acesso deve
  ser combinado com quem administra o SEI.
- PDFs impressos pela impressora "Microsoft Print to PDF" saem sem a proteção do aplicativo. Use os
  botões de exportar e gerar.
- A cadeia de custódia apoia, mas não substitui, o procedimento pericial oficial.
