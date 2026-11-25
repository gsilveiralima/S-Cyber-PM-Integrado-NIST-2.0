# S-Cyber 2.0 — plataforma integrada de defesa cibernética (NIST CSF 2.0)

O S-Cyber verifica a segurança de um computador Windows e de uma assinatura do Microsoft Azure **em um clique, só com leitura**. Cada problema vem explicado em linguagem simples, com prioridade, recomendação e ligação ao **NIST Cybersecurity Framework 2.0**. Depois da correção, uma nova verificação **comprova a melhoria**.

O núcleo é um só, com duas modalidades definidas pela licença assinada:

| Modalidade | Para quem | Diferença |
|---|---|---|
| **S-Cyber Business** | Pequenas e médias empresas do comércio, serviços e turismo; INOVA Senac | Sem as integrações institucionais (SEI) |
| **S-Cyber PM** | Polícia Militar do Estado de Goiás, mediante autorização | Inclui as integrações institucionais |

> **Situação (24/11/2026):** **pré-lançamento** do S-Cyber 2.0, versão 2.0.0. **Homologado apenas no Windows 10/11 (64 bits).** O que foi testado, e como, está no [relatório de auditoria e homologação](docs/AUDITORIA_S-CYBER_2.0.md). As versões para Linux e macOS não fazem parte desta entrega.

## Instalação

### Usuário final (sem Python e sem comandos)

1. Abra a página **[Releases](https://github.com/gsilveiralima/S-Cyber-PM-Integrado-NIST-2.0/releases)** e baixe, da versão mais recente:
   - o `SCyberPM-Setup-<versão>.exe`;
   - o `SHA256SUMS.txt`.
2. Confira a integridade no PowerShell com `Get-FileHash .\SCyberPM-Setup-2.0.0.exe -Algorithm SHA256`. O resultado precisa ser igual ao do `SHA256SUMS.txt`.
3. Dê dois cliques no instalador. Ele **não pede administrador**: o programa vai para `%LOCALAPPDATA%\Programs\S-Cyber PM` e cria os atalhos no menu Iniciar.
   - O instalador ainda não é assinado. Se o Windows mostrar "O Windows protegeu o computador", clique em **Mais informações** e depois em **Executar assim mesmo**.
4. **Ative a instalação.** Na primeira abertura, clique em **Enviar pedido por e-mail**: o pedido vai pronto para o suporte (`scybersuporte@gmail.com`). Quando a resposta chegar, cole a chave de ativação e clique em **Ativar**.
5. **Certificado e senhas.** Escolha o seu certificado credenciado. Num perfil novo, crie as senhas: não existe senha de fábrica.
6. **Primeiro diagnóstico.** Vá em **NIST Intelligence → Diagnóstico inteligente**. Se abrir o programa como administrador, ele verifica mais itens, como BitLocker, SMBv1 e Secure Boot.

O guia completo, com telas e solução de problemas, está em **[docs/GUIA_WINDOWS_INSTALADOR.md](docs/GUIA_WINDOWS_INSTALADOR.md)**.

### Administradores (SGT Gabriel e MAJ Leonídio)

Os administradores emitem, renovam, transferem e revogam licenças com o próprio certificado administrativo. A chave privada desse certificado nunca sai do Windows de quem o tem.

- **Tela do administrador (sem PowerShell):** dois cliques em `S-Cyber-PM-Integrado/Administrar licencas.bat`. Cole o pedido que chegou por e-mail e clique em **Emitir licença**: a resposta pronta (instruções + chave) já fica copiada para responder ao e-mail. A pessoa cola a chave na tela de ativação, sem precisar de arquivo. A mesma tela credencia certificados e renova as listas.
- **Linha de comando** (renovar, transferir, revogar):
  ```powershell
  .\.venv\Scripts\python.exe admin_licencas.py emitir --pedido "SCPM-PEDIDO-ATIVACAO...." --unidade "Empresa X" --modalidade business --organizacao "Empresa X Ltda" --dias 365 --saida licenca.sclic
  ```

- **Listas assinadas:** a pasta `S-Cyber-PM-Integrado/licencas/` guarda as listas públicas: administradores, revogações e credenciamentos. Os aplicativos instalados baixam essas listas daqui.
- **Validade:** as listas valem 30 dias. Renove no máximo a cada 3 semanas, pela tela (**Renovar listas** e depois **Enviar ao GitHub**) ou com `admin_licencas.py publicar`. Um aviso diário do GitHub chega por e-mail quando faltam 10 dias.
- **Passo a passo:** [docs/ADMINISTRACAO_LICENCAS.md](docs/ADMINISTRACAO_LICENCAS.md).

### Desenvolvimento (pelo código-fonte)

Use o Windows PowerShell com Python 3.12 ou superior:

```powershell
git clone https://github.com/gsilveiralima/S-Cyber-PM-Integrado-NIST-2.0.git
cd .\S-Cyber-PM-Integrado-NIST-2.0\S-Cyber-PM-Integrado
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
.\.venv\Scripts\python.exe -m unittest discover -s tests
.\.venv\Scripts\python.exe appSCyberPM.py
```

**Validação completa numa máquina Windows:** rode `powershell -ExecutionPolicy Bypass -File .\validar_no_windows.ps1`. Ele executa os testes, gera o executável e o instalador, instala, mede a abertura e grava o `RESULTADO.txt` na Área de Trabalho. Feche o S-Cyber PM antes.

**Publicar uma versão:** o CI (GitHub Actions) testa e gera o instalador em todo push. Há dois jeitos de publicar:
- **Pelo site:** abra *Releases → Draft a new release*, digite uma tag nova (por exemplo `v2.0.0-beta.2`) sobre a `main`, marque *Set as a pre-release* e publique. O CI gera o instalador e o anexa à Release em cerca de 5 minutos.
- **Pelo terminal:** rode `git tag v2.0.0-beta.2 && git push origin v2.0.0-beta.2`. O CI cria a Release sozinho.

O passo a passo antigo, com problemas encontrados e soluções, está em [docs/INSTALACAO_WINDOWS.md](docs/INSTALACAO_WINDOWS.md).

## O que o S-Cyber 2.0 faz

- **Diagnóstico Inteligente em um clique.**
  - Verifica 17 itens do Windows, só com leitura.
  - Cria um achado ligado ao NIST para cada problema, com prioridade dada por regra documentada.
  - Mostra recomendações com o passo a passo da correção e de como confirmá-la.
  - Compara cada verificação com a anterior e mostra o que melhorou ou piorou.
  - Tem modo básico, para leigos, e avançado, com evidência em SHA-256, subcategorias NIST e histórico.
- **Nuvem Microsoft Azure, só com leitura.**
  - Verifica armazenamento público, criptografia, regras de rede abertas à internet, proprietários da assinatura, backup e exportação de logs.
  - Usa o Azure CLI já conectado, com o papel Leitor.
  - Tem uma demonstração simulada, sempre identificada como simulada.
- **Corujinha.** Gera um inventário detalhado, só com o consentimento do usuário. Câmera, captura de tela e internet vêm desligadas por padrão, e os processos aparecem com o PID.
- **Licenças assinadas.**
  - Ativação offline e recusa de licença revogada.
  - Modalidade Business ou PM.
  - Recuperação dos dados mesmo sem licença válida.
- **Segurança.**
  - Login por certificado, com desafio e resposta.
  - Sem senha de fábrica.
  - Papéis definidos pela sessão autenticada, não pela interface.
  - Banco cifrado com AES-256-GCM.
  - Trilha de auditoria encadeada por hash.

## Documentação

| Documento | Conteúdo |
|---|---|
| [docs/INOVA_2026.md](docs/INOVA_2026.md) | **INOVA 2026 (Prêmio Atena)**: equipe, prazos, proposta pelos 5 critérios, checklist de envio e roteiro do pitch |
| [docs/AUDITORIA_S-CYBER_2.0.md](docs/AUDITORIA_S-CYBER_2.0.md) | **S-Cyber 2.0**: auditoria, fases executadas, testes e medições no Windows, limitações |
| [docs/GUIA_WINDOWS_INSTALADOR.md](docs/GUIA_WINDOWS_INSTALADOR.md) | Guia curto do usuário: instalador, ativação, certificado, achados, diagnóstico |
| [docs/ADMINISTRACAO_LICENCAS.md](docs/ADMINISTRACAO_LICENCAS.md) | Licenças e credenciamentos (somente SGT Gabriel e MAJ Leonídio) |
| [docs/INSTALACAO_WINDOWS.md](docs/INSTALACAO_WINDOWS.md) | Instalação passo a passo e solução de problemas |
| [S-Cyber-PM-Integrado/CERTIFICADOS.md](S-Cyber-PM-Integrado/CERTIFICADOS.md) | Certificados autorizados, inclusão de usuário, AC institucional |
| [S-Cyber-PM-Integrado/GUIA_NIST_INTELLIGENCE.md](S-Cyber-PM-Integrado/GUIA_NIST_INTELLIGENCE.md) | Uso de cada aba do painel NIST |
| [docs/PRODUCAO_SEGURANCA.md](docs/PRODUCAO_SEGURANCA.md) | Senhas, certificados e configuração para produção |
| [S-Cyber-PM-Integrado/INSTRUCOES_INTEGRACAO.md](S-Cyber-PM-Integrado/INSTRUCOES_INTEGRACAO.md) | O que foi integrado, arquivos alterados, limites |
| [docs/VALIDACAO_WINDOWS_2026-11-22.md](docs/VALIDACAO_WINDOWS_2026-11-22.md) | Resultado dos testes no Windows 11 |
| [docs/CHANGELOG_v1.6.0.md](docs/CHANGELOG_v1.6.0.md) | Mudanças desta versão (e changelogs anteriores em `docs/`) |

## Estrutura

```
S-Cyber-PM-Integrado/            aplicação (execute appSCyberPM.py daqui)
  appSCyberPM.py                 abertura, certificado, login e janela principal
  nist_intelligence/             módulo NIST (catálogo, avaliação, coleta, relatório, SEI, criptografia)
  formNISTIntelligence.py        ligação do painel NIST com a janela principal
  formTrocaSenha.py              criação das senhas no 1º acesso
  adicionar_certificado.py       inclui um usuário na lista de certificados
  verificar_certificados.ps1     diagnóstico dos certificados deste Windows
  requirements-lock.txt          versões exatas validadas
  iniciar_nist_windows.bat       abre o S-Cyber PM direto no painel NIST
  coletor_nist.ps1               coletor avulso para computadores sem o S-Cyber PM
  coletar_nist_windows.bat       executa o coletor avulso (como Administrador)
  nist_intelligence/diagnostico.py  Diagnóstico Inteligente (motor) · nuvem.py: Azure somente leitura
  modPowerShell.py · modCaminhos.py  execução única do PowerShell · pastas de dados
  licencas/                      listas públicas assinadas pelos administradores
  validar_no_windows.ps1         validação completa numa máquina Windows
  tests/                         155 testes automáticos (rodam também no GitHub Actions, no Windows)
docs/                            instalação, validação, segurança e changelogs
```

## O que o módulo NIST Intelligence faz (base do S-Cyber 1.6)

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
- **Equipe do Projeto Integrador / INOVA 2026** (Técnico em Defesa Cibernética, Senac Cora Coralina, Goiânia – GO):
  Leonídio Alves De Moraes Junior, Daniel Otavio De Lima Medrado, Juliano Porto De Souza,
  Juliano Santos Borges e Gabriel Silveira Lima, com a docente Fabiana Fernandes Harami. Detalhes em [docs/INOVA_2026.md](docs/INOVA_2026.md).

Todo o conteúdo deste repositório, inclusive os arquivos da aplicação original S-Cyber PM, é
distribuído sob a **licença Apache 2.0** (arquivo `LICENSE`), com a concordância do MAJ Leonidio Alves
de Moraes Junior, registrada em 22/11/2026.

O arquivo `S-Cyber-PM-Integrado/README.md` é o README da aplicação original, mantido sem alterações para conferência de
integridade (SHA-256). Ele ainda traz a restrição de redistribuição do repositório original e
descreve a versão anterior: o S-Cyber 2.0 está descrito neste README e em `docs/`. Neste
repositório, essa restrição não se aplica: vale a Apache 2.0 descrita acima.
