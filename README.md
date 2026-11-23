# S-Cyber PM Integrado — NIST CSF 2.0

Cópia integrada do **S-Cyber PM 1.5** (Cryptography and Digital Certificate Framework) com o
módulo **S-Cyber NIST Intelligence 1.2.0**, que leva o NIST Cybersecurity Framework 2.0 para dentro
da aplicação.

> **Situação:** versão para uso real, validada no Windows 11 em 22/11/2026
> ([registro da validação](docs/VALIDACAO_WINDOWS_2026-11-22.md)). Desenvolvimento conjunto do
> MAJ Leonídio e do SGT Gabriel, com autorização da PMGO para uso nos sistemas corporativos.

Este projeto de extensão foi apresentado ao Programa de Reconhecimento INOVA (Senac) e tem como base a
monografia *Aplicação do NIST Cybersecurity Framework na cibersegurança da Polícia Militar: um estudo
de caso (simulado) com OSINT na PMGO*.

## Instalação

O passo a passo validado, com os problemas encontrados e as soluções, está em
**[docs/INSTALACAO_WINDOWS.md](docs/INSTALACAO_WINDOWS.md)**. Em resumo (PowerShell, sem Git):

```powershell
cd $HOME\Downloads
Invoke-WebRequest https://github.com/gsilveiralima/S-Cyber-PM-Integrado-NIST-2.0/archive/refs/heads/main.zip -OutFile scyber-pm.zip
Expand-Archive scyber-pm.zip -DestinationPath scyber-pm -Force
cd .\scyber-pm\S-Cyber-PM-Integrado-NIST-2.0-main\S-Cyber-PM-Integrado
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
.\.venv\Scripts\python.exe -m unittest discover -s tests        # 77 testes OK
powershell -ExecutionPolicy Bypass -File .\verificar_certificados.ps1
.\.venv\Scripts\python.exe appSCyberPM.py --nist     # abre direto no painel NIST
```

Cada usuário precisa de um **certificado autorizado com a chave privada** no próprio Windows
(ver [CERTIFICADOS.md](S-Cyber-PM-Integrado/CERTIFICADOS.md)). No primeiro acesso, o aplicativo obriga
a trocar a senha de fábrica. Depois do login, o painel NIST abre sozinho (com `--nist`), com
**Ctrl+Shift+N**, pelo menu **NIST Intelligence** ou pelo assistente.

## Documentação

| Documento | Conteúdo |
|---|---|
| [docs/INSTALACAO_WINDOWS.md](docs/INSTALACAO_WINDOWS.md) | Instalação passo a passo e solução de problemas |
| [S-Cyber-PM-Integrado/CERTIFICADOS.md](S-Cyber-PM-Integrado/CERTIFICADOS.md) | Certificados autorizados, inclusão de usuário, AC institucional |
| [S-Cyber-PM-Integrado/GUIA_NIST_INTELLIGENCE.md](S-Cyber-PM-Integrado/GUIA_NIST_INTELLIGENCE.md) | Uso de cada aba do painel NIST |
| [docs/PRODUCAO_SEGURANCA.md](docs/PRODUCAO_SEGURANCA.md) | Senhas, certificados e configuração para produção |
| [S-Cyber-PM-Integrado/INSTRUCOES_INTEGRACAO.md](S-Cyber-PM-Integrado/INSTRUCOES_INTEGRACAO.md) | O que foi integrado, arquivos alterados, limites |
| [docs/VALIDACAO_WINDOWS_2026-11-22.md](docs/VALIDACAO_WINDOWS_2026-11-22.md) | Resultado dos testes no Windows 11 |
| [docs/CHANGELOG_v1.2.0.md](docs/CHANGELOG_v1.2.0.md) | Mudanças desta versão (e changelogs anteriores em `docs/`) |

## Estrutura

```
S-Cyber-PM-Integrado/            aplicação (execute appSCyberPM.py daqui)
  appSCyberPM.py                 abertura, certificado, login e janela principal
  nist_intelligence/             módulo NIST (catálogo, avaliação, coleta, relatório, SEI, criptografia)
  formNISTIntelligence.py        ligação do painel NIST com a janela principal
  formTrocaSenha.py              troca obrigatória da senha de fábrica
  adicionar_certificado.py       inclui um usuário na lista de certificados
  verificar_certificados.ps1     diagnóstico dos certificados deste Windows
  requirements-lock.txt          versões exatas validadas
  iniciar_nist_windows.bat       abre o S-Cyber PM direto no painel NIST
  coletor_nist.ps1               coletor avulso para computadores sem o S-Cyber PM
  coletar_nist_windows.bat       executa o coletor avulso (como Administrador)
  tests/                         77 testes automáticos (rodam também no GitHub Actions, no Windows)
docs/                            instalação, validação, segurança e changelogs
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
  (Res. CD/ANPD nº 15/2024) e linha do tempo encadeada por hash. O prazo desconta os feriados
  nacionais e os estaduais ou municipais cadastrados.
- Guarda **evidências** com SHA-256 e cadeia de custódia à prova de adulteração.
- Registra indícios de **OSINT** defensivo e faz consultas somente leitura ao **SEI**.
- Gera um **relatório PDF** que pode ser assinado com o certificado do S-Cyber PM e protegido com senha.
- Mantém uma **trilha de auditoria** de quem fez cada alteração (usuário, Windows e certificado),
  encadeada por hash.
- Refaz a **coleta técnica sozinho** a cada 7 dias, compara com a anterior e aplica o resultado na avaliação.
- Liga os **incidentes aos processos do SEI** e faz **backup e restauração** do banco cifrado.
- **Cifra o banco de dados** com uma chave derivada do certificado do S-Cyber PM.
- Avalia **vários computadores**: um coletor avulso roda nos computadores sem o S-Cyber PM, e o
  resultado é importado no painel.
- **Consolida várias unidades** com pacotes assinados pelo certificado e cifrados com senha, que
  levam só dados minimizados.
- Liga **evidências às subcategorias** da avaliação.
- Faz **cópia automática diária**, avisa por **notificação do Windows** sobre prazos e sobre a
  validade do certificado, e aplica a **retenção** de incidentes encerrados (LGPD).
- Tem **tour narrado** (Arquivo > Tour ou `F2`) que apresenta o painel aba por aba e explica o uso.

## Segurança

- Os textos do banco do módulo (`%APPDATA%\SCyberPM\nist\nist.db`) são **cifrados com AES-256-GCM**.
  A chave deriva do certificado do S-Cyber PM e não fica gravada em lugar nenhum: sem o certificado
  com a chave privada, o banco não pode ser lido. Números, datas, situações e hashes continuam em claro,
  porque são usados em prazos e filtros.
- A proteção vale para o arquivo em disco. Quem abre o S-Cyber PM com o certificado e a senha de
  acesso lê os dados normalmente. Registre só o necessário.
- A coleta técnica só lê dados: não altera configurações e não lê senhas.
- Nenhuma chave privada faz parte deste repositório. O arquivo `.cer` contém apenas a chave pública,
  e os thumbprints da lista são públicos por natureza.
- Login com certificado (desafio e resposta), senha forte obrigatória e PDFs assinados e cifrados.

## Autoria e licença

- **S-Cyber PM** (aplicação original): MAJ Leonidio Alves de Moraes Junior, MAJ Daniel Medrado e
  SGT Gabriel Silveira Lima — PMGO. Repositório original:
  [Leonidiojr/S-Cyber-prj](https://github.com/Leonidiojr/S-Cyber-prj).
- **S-Cyber NIST Intelligence** (módulo NIST, `nist_intelligence/` e arquivos relacionados):
  SGT Gabriel Silveira Lima.

Todo o conteúdo deste repositório, inclusive os arquivos da aplicação original S-Cyber PM, é
distribuído sob a **licença Apache 2.0** (arquivo `LICENSE`), com a concordância do MAJ Leonidio Alves
de Moraes Junior, registrada em 22/11/2026.

O arquivo `S-Cyber-PM-Integrado/README.md` foi preservado sem alterações, para conferência de
integridade (SHA-256), e ainda traz a restrição de redistribuição do repositório original. Neste
repositório, essa restrição não se aplica: vale a Apache 2.0 descrita acima.
