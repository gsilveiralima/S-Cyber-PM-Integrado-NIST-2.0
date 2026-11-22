# S-Cyber PM Integrado — NIST CSF 2.0

Cópia integrada do **S-Cyber PM** (Cryptography and Digital Certificate Framework) com o módulo
**S-Cyber NIST Intelligence v0.4.0**, que leva o NIST Cybersecurity Framework 2.0 para dentro da
aplicação.

Este projeto de extensão foi apresentado ao Programa de Reconhecimento INOVA (Senac) e tem como base a
monografia *Aplicação do NIST Cybersecurity Framework na cibersegurança da Polícia Militar: um estudo
de caso (simulado) com OSINT na PMGO*.

## Estrutura

```
S-Cyber-PM-Integrado/          aplicação (execute appSCyberPM.py daqui)
  nist_intelligence/           módulo NIST (catálogo, avaliação, coleta, relatório, SEI)
  formNISTIntelligence.py      ponto de integração com a janela principal
  tests/                       testes automáticos do módulo
  GUIA_NIST_INTELLIGENCE.md    guia de uso
  INSTRUCOES_INTEGRACAO.md     o que foi integrado e como executar
docs/                          changelogs e manifesto de integridade
```

## O que o módulo NIST Intelligence faz

- Avalia as **106 subcategorias** do CSF 2.0 com maturidade atual e alvo (0–4), responsável e prazo.
  Também registra o **Tier** (1–4) de cada função.
- Faz uma **coleta técnica automática**, somente leitura, do Windows: antivírus, firewall, BitLocker,
  UAC, RDP, SMBv1, atualizações, contas, política de senha, logs, portas abertas e validade do
  certificado. Cada resultado é ligado às subcategorias.
- Monta um **plano de ação** priorizado pelas lacunas e pelas falhas técnicas.
- Mantém um **registro de riscos** na matriz ordinal 1–3, com tratamento, risco residual e mapa de calor.
- Acompanha **incidentes** pelas fases de resposta, com prazo de comunicação à ANPD
  (Res. CD/ANPD nº 15/2024) e linha do tempo encadeada por hash.
- Guarda **evidências** com SHA-256 e cadeia de custódia à prova de adulteração.
- Registra indícios de **OSINT** defensivo e faz consultas somente leitura ao **SEI**.
- Gera um **relatório PDF** que pode ser assinado com o certificado do S-Cyber PM e protegido com senha.

## Executar (Windows 10/11, Python 3.11+)

```powershell
cd S-Cyber-PM-Integrado
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe appSCyberPM.py
```

O S-Cyber PM exige o certificado autorizado, com a chave privada, no repositório **Pessoal** do
Windows (veja `S-Cyber-PM-Integrado/CERTIFICADO_ORIGINAL_VERIFICACAO.md`). Depois do login, abra
**NIST Intelligence** pela Ribbon, pelo menu ou com **Ctrl+Shift+N**.

Para testar só o painel NIST, sem o login e com um banco temporário:

```powershell
$env:SCYBER_NIST_DEV=1; .\.venv\Scripts\python.exe teste_painel_nist.py
```

Testes automáticos: `py -3 -m unittest discover -s tests -v`, dentro de `S-Cyber-PM-Integrado`.

## Segurança

- O banco do módulo (`%APPDATA%\SCyberPM\nist\nist.db`) **não é cifrado**. Não registre conteúdo
  sigiloso, pessoal ou policial.
- A coleta técnica só lê dados: não altera configurações e não lê senhas.
- Nenhuma chave privada faz parte deste repositório. O arquivo `.cer` contém apenas a chave pública.

## Autoria e licença

- **S-Cyber PM** (aplicação original): MAJ Leonidio Alves de Moraes Junior, MAJ Daniel Medrado e
  SGT Gabriel Silveira Lima — PMGO. Repositório original:
  [Leonidiojr/S-Cyber-prj](https://github.com/Leonidiojr/S-Cyber-prj).
- **S-Cyber NIST Intelligence** (módulo NIST, `nist_intelligence/` e arquivos relacionados):
  SGT Gabriel Silveira Lima.

A licença Apache 2.0 do arquivo `LICENSE` se aplica ao módulo NIST Intelligence. Os arquivos da
aplicação original S-Cyber PM continuam sob os termos definidos por seus autores; veja
`S-Cyber-PM-Integrado/README.md`.
