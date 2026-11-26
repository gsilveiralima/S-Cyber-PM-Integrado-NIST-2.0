# S-Cyber 2.0 — Auditoria técnica e linha de base (Fase 1)

**Situação:** proposta de desenvolvimento. Esta não é uma versão homologada.

- **Data:** 24/11/2026.
- **Base analisada:** `main` do repositório `gsilveiralima/S-Cyber-PM-Integrado-NIST-2.0`, commit
  `612348561722ccc7069b19d3de24126363ba56a7` (24/11/2026 10:59 −03, "Merge PR #10"). Versões
  declaradas: S-Cyber PM `1.6`, NIST Intelligence `1.3.0`.
- **Cópia local independente:** a cópia foi clonada com o envio bloqueado
  (`git remote set-url --push origin DESATIVADO-sem-autorizacao`).
- **Operações remotas:** nenhuma foi feita nesta fase. Não houve push, merge, criação de branch remota
  nem publicação.

## 1. Objetivo
Estabelecer uma referência verificável do que existe e do que funciona. Identificar falhas críticas de
instalação e segurança, classificar as funcionalidades e propor uma refatoração incremental para o
S-Cyber 2.0, um núcleo único com duas modalidades: Business e PM.

## 2. Comandos executados (reprodutíveis)
```
git clone https://github.com/gsilveiralima/S-Cyber-PM-Integrado-NIST-2.0.git scyber2
git -C scyber2 remote set-url --push origin DESATIVADO-sem-autorizacao
cd scyber2/S-Cyber-PM-Integrado
python3 -I -m unittest discover -s tests              # linha de base
ruff check --select E9,F .                            # regras do CI
ruff check --select B,S,C901,PERF --statistics .      # análise ampla
python3 -I -X importtime -c "import nist_intelligence.core"   # (e demais módulos)
```
**Ambiente da auditoria:**
- Linux, Python 3.12, sem tkinter e sem acesso à rede para instalar pacotes.
- Os testes exclusivos de Windows rodam no CI do GitHub Actions. Ele **não foi acionado** nesta fase,
  porque o push não está autorizado.

## 3. Linha de base medida

| Métrica | Valor | Observação |
|---|---|---|
| Arquivos Python / linhas | 71 / 36.951 | 24 arquivos com mais de 500 linhas |
| Maiores arquivos | `formCoruja.py` 2.286 · `formNavegador.py` 1.806 · `formSei.py` 1.778 · `nist_intelligence/main.py` 1.750 · `formSpy.py` 1.481 | |
| Testes automatizados | **110 em 5,2 s, OK** (6 pulados) | Os 6 pulados: 4 exigem Windows, 1 é a consulta real às fontes (só no CI) e 1 exige tkinter |
| Testes no CI Windows (última execução, PR #10) | 110 em 111 s, OK | Inclui assinatura real pelo .NET e o coletor avulso |
| Lint do CI (E9, F) | 0 ocorrências | |
| Lint amplo | 46 funções complexas (C901) · 32 SQL montados com f-string (S608) · 32 `raise` sem `from` (B904) · 20 `try/except/pass` silenciosos (S110) | Os S608 usam nomes de tabela internos; nenhum recebe entrada do usuário |
| Importação (Linux) | core 25 ms · fontes 47 ms · licença 54 ms · relatório 114 ms | O tempo de inicialização no Windows **não foi medido** |
| Artefato do instalador (CI) | 123.162.738 bytes (zip com instalador, executável e logs) | O tamanho de cada arquivo e o tempo de instalação **não foram medidos** |
| Dependências diretas | 8 declaradas + 2 não declaradas (`selenium`, `pypdfium2`); lock com 27 pacotes | |
| Recursos multimídia | `Surveillance Pulse.mp3` 4,7 MB · `logo.png` 572 KB | |

## 4. O que efetivamente funciona (evidência existente)
- **Validado pelo usuário no Windows 11 em 22/11/2026:**
  - certificado com desafio e resposta;
  - troca obrigatória da senha de fábrica;
  - opções e banco NIST cifrados (AES-256-GCM);
  - coleta técnica real;
  - PDF assinado e protegido.
- **Validado no CI Windows (24/11):**
  - instalador gerado, instalado, aberto pelo destino do atalho em modo diagnóstico, atualizado e
    desinstalado;
  - assinatura .NET conferida em Python;
  - consulta real às fontes. Resultados: KEV CVE-2024-3400 encontrada; HIBP com o vazamento Adobe de
    04/10/2013; Pwned Passwords com 6.421.554 ocorrências de `P@ssw0rd`.
- **Implementado, mas não homologado na interface real:**
  - ativação por licença;
  - credenciamento;
  - assistente de perfil;
  - fluxo de ativos e achados;
  - GitHub secret scanning (sem token real nos testes);
  - HIBP por domínio (bloqueado: falta a chave paga).

## 5. Falhas e riscos encontrados

### 5.1 Crítica — corrigida nesta fase (somente na cópia local)
**O banco NIST era alterado antes da conferência da chave.**
- **O problema:** `core.connect()` criava tabelas e colunas novas e só depois comparava a chave. Com o
  certificado errado, ou sem chave, um banco cifrado de versão anterior recebia a alteração de esquema
  antes da recusa.
- **A correção:** a chave agora é conferida em modo somente leitura (`key_status`) antes de qualquer
  gravação.
- **A prova:** o teste `tests/test_auditoria_fase1.py` compara o SHA-256 do arquivo antes e depois de
  tentar abri-lo com a chave errada e sem chave.

  | Situação | Resultado do teste |
  |---|---|
  | Sem a correção | FALHA — hash diferente |
  | Com a correção | OK |

  A suíte completa continua OK: 111 testes.

### 5.2 Segurança — a tratar

| # | Risco | Situação atual | Recomendação | Fase |
|---|---|---|---|---|
| S1 | O papel (revisor, administrador) é passado pela interface às regras de negócio | `achados.review(..., role)` confia no parâmetro recebido | Sessão autenticada central (`core/auth`), com o papel derivado do certificado validado; as regras leem da sessão | 2 |
| S2 | Uma licença expirada bloqueia o aplicativo inteiro | Os dados não se perdem, mas ficam inacessíveis até a renovação (contraria o §17) | Modo de recuperação somente leitura, com exportação e backup, registrado na auditoria | 2 |
| S3 | A licença não tem modalidade nem funcionalidades | Só vincula a instalação | Incluir os campos `modalidade` (business/pm) e `funcionalidades` na licença assinada | 7 |
| S4 | A cadeia de hash local pode ser recalculada por quem tem a chave (a retenção recalcula de propósito) | Detecta adulteração ingênua | Pontos de verificação: o hash do fim da cadeia assinado com o certificado, guardado no pacote de consolidação e no relatório | 7 |
| S5 | A senha de fábrica está no código (`SENHA_PADRAO`) | Mitigada pela troca obrigatória no 1º acesso | Remover a senha de fábrica: a senha é criada no 1º acesso, depois do certificado | 2 |
| S6 | Um administrador pode remover o outro | Registrado e assinado no repositório público | Exigir as duas assinaturas para remover um administrador | 7 |
| S7 | A Corujinha roda processos ocultos e "protegidos contra captura" | É uma demonstração | Comportamento típico de malware: pode acionar antivírus e EDR e contraria a transparência. Tornar visível e consentido | 4 |
| S8 | O instalador não é assinado | O Windows mostra aviso de proteção (SmartScreen) | Assinatura de código institucional; **sem** desativar o SmartScreen | 8 |
| S9 | As credenciais externas ficam no banco do usuário | Cifradas com o certificado; só revisor ou administrador as configura | Aceitável no piloto; a solução definitiva é um serviço da organização | 5 |

### 5.3 Instalação, desempenho e manutenção

| # | Problema | Evidência | Recomendação | Fase |
|---|---|---|---|---|
| M1 | Build não reprodutível | O CI e o instalador usam `requirements.txt` (`>=`) com Python 3.12; o lock foi validado com 3.14 | Um lock por versão de Python, usado pelo CI e pelo instalador | 2 |
| M2 | Dependências não declaradas | `selenium` (SEI) e `pypdfium2` (miniatura do PDF); `numpy` declarado sem import direto | Declarar como opcionais por modalidade; tirar o `numpy` direto | 2 |
| M3 | Versões inconsistentes | Cabeçalhos com "1.5", `APP_VERSAO` com 1.6, `formSplashScreen.py` com "Version 1.0", lock com "NIST 1.0.0" | Fonte única de versão | 2 |
| M4 | Execução de PowerShell duplicada | Pelo menos 6 implementações (`formListCerts`, `modHello`, `formGerenciadorUsuarios`, `modDiagnostico`, `collector`, `notificacoes`) | Adaptador único `plataforma/windows` (timeout, PSModulePath, texto codificado) | 3 |
| M5 | Pasta de dados definida em 3 lugares | `modRecursos.pasta_dados`, `modPerfil.pasta_dados`, `core.DATA` | Módulo único de caminhos, preparado para isolar por organização | 3 |
| M6 | Diagnóstico de sistema duplicado | Corujinha (inventário em texto) × `collector` (verificações ligadas ao NIST) | Um motor de diagnóstico; a Corujinha vira uma das visualizações | 4 |
| M7 | Menu e Ribbon duplicados | O mesmo comando em dois lugares; "Sair" em 4 abas | Um registro único de comandos, organizado nas 5 áreas | 6 |
| M8 | Interface bloqueada por chamadas síncronas | PowerShell e rede dentro de eventos da janela (`formListCerts`, `modHello`, `formGerenciadorUsuarios`, `modSenhaVazada` até 8 s) | Executor em segundo plano com progresso e cancelamento | 3 |
| M9 | Código morto | `formSplashScreen.py` não é importado por nenhum módulo | Descontinuar, mediante aprovação | 3 |
| M10 | Núcleo preso ao Windows | Certificados (`Cert:\CurrentUser\My`), `winreg`, `pywin32` e PowerShell dentro do núcleo NIST | Adaptadores por plataforma; o núcleo fica independente | 8 |

## 6. Classificação das funcionalidades

| Funcionalidade | Arquivos | Classificação | Destino no S-Cyber 2.0 |
|---|---|---|---|
| Certificado, login e opções cifradas | appSCyberPM, formLogin, formOpcoes, modHello | **Manter / Refatorar** | Núcleo `auth` (S1, S5) |
| Ativação, credenciamento, diagnóstico e perfil | modLicenca, admin_licencas, modDiagnostico, modPerfil, formAbertura | **Manter / Refatorar** | Administração e assistente de primeiro acesso (S2, S3) |
| NIST: avaliação, riscos, incidentes, evidências, auditoria, consolidação | nist_intelligence/* | **Integrar** | Camada transversal; o motor ativo → achado já existe |
| Coleta técnica e coletor avulso | collector | **Integrar** | Base do Diagnóstico Inteligente |
| Corujinha (relatório do sistema) | formCoruja (2.286 linhas) | **Refatorar** | Inventário dentro do diagnóstico; animação **opcional**; ocultação **descontinuar mediante aprovação** |
| Espião (o que um observador vê) | formSpy | **Integrar / Tornar opcional** | As verificações defensivas (conexões, área de transferência) entram no diagnóstico; o resto é didático |
| Listar certificados, assinar documentos, PDF protegido | formListCerts, formSign, modPDFProtegido | **Manter** | Operações e Administração |
| Hash SHA-256 | formHash | **Integrar** | Integridade de arquivos, ligada às evidências |
| Pesquisar arquivos | formPesquisaArquivos | **Otimizar** | Operações |
| Compactar em partes; ferramentas de PDF | formParticionar, formDividirPdf, modPDFDividir | **Tornar opcional** | Não fazem parte do núcleo de defesa |
| Navegador seguro (WebView2 / pythonnet) | formNavegador | **Tornar opcional** | Só Windows; dependência pesada |
| SEI | formSei, formExploreSEI, bridge | **Integrar (só PM)** | Integração institucional; declarar o `selenium` |
| Ponta a ponta e rádio digital (simulações) | formE2E, formRadio | **Tornar opcional** | "Treinamento" (UC5); fora da modalidade Business |
| Memória, disco e processador (didáticos) | formMemoria, formDisco, formProcess | **Tornar opcional** | "Treinamento" |
| Tour narrado, voz, destaque e música | formTour, modDestaque, modSom, mp3 de 4,7 MB | **Tornar opcional**; música: **descontinuar mediante aprovação** | Modo apresentação |
| Gerenciador de usuários locais | formGerenciadorUsuarios | **Integrar** | Verificação de contas e permissões no diagnóstico |
| Assistente de comandos | modAssistente | **Manter** | Busca de comandos |
| Splash antigo | formSplashScreen | **Descontinuar mediante aprovação** | Código morto |

Nada é removido sem a sua aprovação. O que for descontinuado fica no histórico do git e pode voltar.

## 7. Plano de refatoração incremental
Cada fase termina com testes verdes e evidência. Não se avança com falha crítica aberta.

| Fase | Entrega | Critério de aprovação | Depende de |
|---|---|---|---|
| 2 Estabilização | S1, S2, S5, M1, M2, M3; correção 5.1 (**feita**) | A suíte passa; regressões provadas; instalador reprodutível | **CI ou uma máquina Windows** para validar o instalador |
| 3 Refatoração | M4, M5, M8, M9; módulo de caminhos por organização | Mesmo comportamento (testes de regressão); interface sem travar | — |
| 4 Integração | Diagnóstico Inteligente em um clique, com formato padronizado, os estados (observado, suspeita, confirmado, falso positivo, indisponível, pendente, tratado), deduplicação, recomendações por regras e nova verificação com comparação | Cenário mínimo §27, passos 4 a 13, em máquina de teste | Fase 3 |
| 5 Inteligência e nuvem | OSV.dev e Google DNS (DoH) no `fontes.py` existente; monitoramento durante o uso; **um** provedor de nuvem, somente leitura, com ambiente de demonstração simulado | Consulta real registrada; verificações de nuvem com evidência | **Escolha do provedor e conta autorizada** |
| 6 Experiência | 5 áreas, modo básico e avançado (mesmos dados), assistente de primeiro acesso, indicadores históricos com metodologia | Usuário leigo conclui o cenário sem terminal | Fase 4 |
| 7 Certificação | Autoridade certificadora privada **offline** (fora do app) emitindo os certificados dos usuários; licença com modalidade e funcionalidades; S4, S6 | Recusa de certificado e de licença adulterados; renovação e revogação testadas | Decisão dos administradores |
| 8 Multiplataforma | Adaptadores; `.deb`/AppImage, `.dmg`; atualização por manifesto assinado | Cada pacote construído e testado **na própria plataforma** | **Runners de CI ou máquinas Linux e macOS** |
| 9 Homologação | Testes em máquina limpa, medições finais, roteiros INOVA e do Projeto Integrador | Relatório de homologação | Docentes e regulamento |

**Duas modalidades, um núcleo:**
- A licença assinada define `modalidade` e `funcionalidades`.
- A modalidade PM habilita o SEI, a AC institucional e a lista de certificados da PMGO.
- A modalidade Business não carrega esses módulos nem as suas configurações.
- Os dados ficam numa pasta por organização (`perfis/<organização>`), com chave própria.

## 8. Bloqueios e limitações desta fase
1. **CI e instaladores.** Com push, merge e branches remotas proibidos, o GitHub Actions não roda. Por
   isso, nada de Windows, macOS ou Linux pode ser construído nem testado a partir daqui. Este ambiente
   também não instala pacotes (o PyInstaller não está disponível). Caminhos possíveis:
   - (a) autorizar uma **branch remota de build**, sem merge;
   - (b) você executar os builds e os testes nas máquinas reais.
2. **Regulamento INOVA.** A página do programa não pôde ser lida por este ambiente, e a busca não
   encontrou o regulamento oficial. É preciso o PDF do regulamento e a orientação dos docentes antes de
   fechar o escopo.
3. **Nuvem.** Não há provedor nem conta autorizada. As verificações reais dependem dessa escolha.
4. **Interface.** Este ambiente não tem tkinter. As telas são exercitadas por um teste com interface
   simulada; a homologação visual precisa de Windows.
5. **Métricas.** As métricas de Windows (tempo de inicialização, memória, tamanho de cada arquivo,
   tempo de instalação) ficam pendentes até haver uma máquina ou CI.

## 9. Fase 2 — estabilização (executada localmente em 24/11/2026)

**Caminho de validação escolhido:** nas máquinas do usuário. Nada vai para o GitHub; o script
`S-Cyber-PM-Integrado/validar_no_windows.ps1` faz a validação no Windows.

| Item | O que mudou | Prova automatizada | Situação |
|---|---|---|---|
| 5.1 | Chave conferida antes de qualquer gravação no banco | `test_auditoria_fase1.ChaveAntesDeGravarTests` (SHA-256 do arquivo igual) | Implementado e testado |
| S1 | Papel da **sessão autenticada** dentro da conexão (`definir_sessao`, definido uma vez só). As regras de achados e fontes leem `db.papel`; a interface não passa mais o papel | `test_achados.SessaoTests` e o fluxo completo com outra sessão para o revisor | Implementado e testado |
| S2 | **Recuperação sem licença:** certificado + senha → backup cifrado, CSVs e MANIFESTO com SHA-256; registrado na auditoria | `test_auditoria_fase1.RecuperacaoSemLicencaTests` | Implementado; não homologado na interface |
| S5 | **Sem senha de fábrica:** num perfil novo, o titular cria as senhas logo após o certificado. Arquivos antigos são reconhecidos pelo SHA-256 da senha antiga e obrigados a trocar | `test_seguranca` (a senha antiga não está mais no código) | Implementado e testado; interface pendente |
| M1 | Script de validação usa `requirements-lock.txt` num ambiente isolado e grava o `pip freeze` | `test_auditoria_fase1.ScriptValidacaoTests` + execução real (seção 10) | Implementado e testado no Windows 11 |
| M2 | `numpy` fora das diretas; `selenium` e `pypdfium2` em `requirements-opcionais.txt` | `ConsistenciaTests.test_dependencias_declaradas` (lê as importações do código) | Implementado e testado |
| M3 | Versão só em `formAbout.APP_VERSAO`; 35 cabeçalhos corrigidos | `ConsistenciaTests.test_versao_fonte_unica` | Implementado e testado |

Testes: 116, todos OK (6 pulados pelos motivos da seção 3). A tela simulada confirmou que um usuário
comum não consegue aprovar um achado e que a sessão de revisor consegue.

Pendente no Windows (executar `validar_no_windows.ps1`):
- instalador e tempos de abertura;
- criação das senhas no primeiro acesso;
- recuperação pela tela;
- papéis pela interface.

## 10. Validação no Windows real (24/11/2026, 14:01–14:04)

**Ambiente:** Windows 11 Pro 10.0.26300 x64, Intel Core i3-13100F, 64 GB de RAM, Python 3.14.8.
Origem: zip da Fase 2, sem git. Executado com `validar_no_windows.ps1` na máquina do usuário.

| Etapa | Resultado | Tempo |
|---|---|---|
| Ambiente isolado com `requirements-lock.txt` + PyInstaller 6.22.3 | OK | 83,8 s |
| Testes automáticos, incluindo os específicos do Windows e a consulta real às fontes | **117 executados, todos OK, nenhum pulado** | 32 s (30,5 s de suíte) |
| Executável (PyInstaller) | OK, 58,2 MB | 66,3 s |
| Instalador (Inno Setup 6.7.3) | OK, `SCyberPM-Setup-1.6.exe` de 59,5 MB | 8,9 s |
| Instalação silenciosa por usuário (sem administrador) | OK | 3,3 s |
| Programa **instalado**, modo diagnóstico, 3 aberturas | OK | 6,33 / 4,07 / 4,04 s |

**Fontes reais consultadas pelos testes:**
- CISA KEV: correspondência;
- HIBP, catálogo de vazamentos: correspondência;
- Pwned Passwords: correspondência para uma senha de teste pública, consultada por k-anonimato.

**SHA-256 dos binários desta execução:**
- executável: `57d5fbb8…f79f44`;
- instalador: `294b1102…54bb20`.

Esses binários não são assinados (S8) e não são reproduzíveis byte a byte, por isso servem só como referência.

**Leitura das metas da seção 26:**
- Instalação: 3,3 s, bem abaixo da meta de cinco minutos.
- Abertura: a meta de até 5 s foi atingida a partir da segunda abertura (cerca de 4 s); a primeira, a frio, levou 6,3 s. O modo diagnóstico não abre a interface nem pede o certificado, então é uma medida aproximada da abertura. A abertura completa pela interface ainda precisa ser cronometrada manualmente.
- Tamanho: 59,5 MB, contra os 123 MB do artefato antigo do CI, que juntava executável e instalador.

**Achados da execução e o que foi corrigido (somente na cópia local):**
1. **Falso FALHOU no script.** No PowerShell 5.1, uma linha que o programa escreve no stderr virava exceção. Corrigido com a função `Rodar`; um teste agora proíbe o redirecionamento `*>`.
2. **Resumo dos testes vazio no RESULTADO e linhas `RemoteException` no log.** O stdout e o stderr chegam fora de ordem, e as linhas vazias do stderr apareciam como `RemoteException`. Corrigido no script.
3. **Diagnóstico contraditório.** O texto mostrava "NÃO ATIVA" e, logo abaixo, "Nenhuma falha informada". Agora a próxima ação pede a ativação. Teste: `test_ativacao.DiagnosticoTests.test_sem_ativacao_a_proxima_acao_e_ativar`.
4. **Observações sem defeito no código:**
   - Na conta do Gabriel, o certificado do Major aparece "sem a chave privada", o que é esperado.
   - O B330B18E… aparece PRONTO PARA USO.
   - 7 certificados de outros aplicativos aparecem como não autorizados, corretamente.
   - Os testes de fontes geram `ResourceWarning`, porque os `HTTPError` simulados não são fechados. É apenas limpeza, a fazer na Fase 5.

**Teste manual pela interface (24/11/2026, 14:13–14:35; evidência: gravações de tela do usuário):**

| Item | Resultado | Situação |
|---|---|---|
| Tela de ativação e "Copiar pedido de ativação" | A tela abre; o pedido é copiado | Homologado |
| Ativação offline | `admin_licencas` emite com o certificado B330B18E; as listas são copiadas para `%LOCALAPPDATA%\SCyberPM\licencas`; aparece "Instalação ativada", e certificado, login e painel NIST abrem com "banco cifrado" | Homologado |
| Recusa de licença revogada | Depois do `revogar`, a tela mostra REVOGADA e reabrir o mesmo `.sclic` é recusado | Homologado |
| Botão de recuperação sem licença | Aparece com a licença revogada; valida o certificado, pede a senha e abre o seletor de pasta | Parcial: a exportação não foi concluída pela interface (está coberta pelo teste automatizado) |
| Reativação com licença nova (`LIC-9F1EE9A144F9`) | Ativa e abre o programa | Homologado |
| Criação das senhas num perfil novo | Não foi possível confirmar pelo vídeo | Pendente |
| Papéis: usuário comum × revisor | Exige um 2º certificado credenciado com o papel `usuario` | Pendente |

**Observações dos testes:**
- As telas de senha não aparecem em gravações (são excluídas da captura de propósito). A evidência dessas telas exige foto do monitor ou relato.
- A janela de senha da recuperação (`simpledialog`) aparece na gravação, ao contrário do login. Os caracteres ficam mascarados, mas o tratamento é inconsistente. A corrigir na Fase 3.
- O seletor de pasta da recuperação confundiu o usuário. Corrigido localmente (commit `33d0f8c`): agora abre na Área de Trabalho e explica que a subpasta é criada sozinha.
- `admin_licencas iniciar` só confere se os arquivos das listas existem, sem checar a validade. A corrigir na Fase 7.
- Nas máquinas de outros usuários, a ativação depende de as listas estarem publicadas na `main` do repositório original. Isso exige push, que depende de autorização expressa.

## 11. Fase 3: refatoração estrutural (executada localmente em 24/11/2026)

Feita só na cópia local, sem nenhuma operação remota. A remoção do código morto e da música foi aprovada expressamente pelo usuário.

| Item | O que mudou | Prova automatizada | Situação |
|---|---|---|---|
| M9 | Removidos o `formSplashScreen.py` (morto), a trilha `Surveillance Pulse.mp3` (4,7 MB) e o `modSom.py`, que só tocava essa música. A Corujinha continua igual, mas sem som. | `test_fase3.RemovidosTests` | Implementado e testado |
| M4 | Novo `modPowerShell.py`, o único lugar que chama o PowerShell, com 10 módulos migrados. Garante: tempo limite sempre (a tela de usuários podia esperar para sempre); saída em UTF-8 (acentos corretos); sem o `PSModulePath` herdado do PowerShell 7; dados passados por variáveis de ambiente ou pela entrada padrão; erros em português. | `test_fase3.PowerShellTests` e `UmSoExecutorTests`, que varre o código e falha se aparecer chamada avulsa | Implementado e testado. No Windows, `test_windows_v12`, o coletor e a assinatura usam o adaptador de verdade |
| M5 | Novo `modCaminhos.py`, fonte única das pastas de dados, do NIST e da instalação, com os mesmos caminhos de antes no Windows. Também ganhou `definir_organizacao()`, que isola os dados por organização (a licença e a identidade continuam na pasta da instalação); ninguém a usa ainda e a Fase 7 vai ligá-la à licença. | `test_fase3.CaminhosTests`, que varre o código e falha se alguém montar a pasta a partir do APPDATA | Implementado e testado |
| M8 | Novo `modRecursos.em_segundo_plano`, executor único para tarefas demoradas. Passaram a rodar em segundo plano: adicionar e excluir certificado; listar e alterar usuários (com proteção contra clique duplo); Windows Hello nas Opções e no login, que agora abre na hora; Pwned Passwords na criação e na troca de senha. | `test_fase3.SegundoPlanoTests` (thread de trabalho × thread da tela, erro, janela fechada) e `SemTravarTests` | Implementado; não homologado na interface |
| Teste manual | As senhas da recuperação e do arquivo PFX agora são pedidas por `pedir_senha`, uma janela protegida contra captura como a do login | `SemTravarTests` | Implementado; não homologado na interface |

**Exceção registrada no M4:** os processos paralelos da Corujinha (Popen com encerramento próprio) continuam como estão. Serão revistos na Fase 4, junto com o S7 (processos ocultos e "protegidos contra captura", que dependem de aprovação).

**Testes:** 132, todos OK, com 8 pulados (exigem Windows, tkinter ou a consulta real às fontes). O lint do CI (E9, F) ficou limpo, e a tela simulada repete os resultados das fases anteriores.

**Validação no Windows (24/11/2026, 14:47–14:51), primeira rodada:**
- **Testes:** 132 executados, todos OK, em 28,8 s. Incluem os testes do Windows (assinatura .NET, coletor) e a consulta real às fontes, já passando pelo `modPowerShell`.
- **Tamanho:** o executável ficou com 53,6 MB (antes 58,2) e o instalador com 54,8 MB (antes 59,5). A redução de 4,7 MB vem da música.
- **Instalação silenciosa: falhou com o código 5.** O log mostra que o S-Cyber PM estava aberto. O instalador pediu que ele fechasse (Restart Manager), esperou 35 s, não conseguiu e desfez a instalação. O diagnóstico seguinte rodou sobre a versão **antiga** ainda instalada, então os tempos dessa rodada não valem para a Fase 3.
- **Correção no script (local):** a etapa agora recusa rodar com o programa aberto, dizendo o PID, e não mede o programa instalado se a instalação falhar.
- **Achado para a Fase 8 (atualização):** o aplicativo não fecha quando o Windows pede. Para atualizar sem reinstalar, o programa precisa responder ao pedido de encerramento, ou o instalador precisa pedir ao usuário que feche o programa, com uma mensagem clara.

**Validação no Windows (24/11/2026, 15:04–15:06), segunda rodada, com o programa fechado:**

| Etapa | Resultado | Tempo |
|---|---|---|
| Testes automáticos (incluem os do Windows e a consulta real às fontes) | 132 executados, todos OK | 32,4 s |
| Executável | OK, 53,6 MB | 67,4 s |
| Instalador | OK, 54,8 MB | 6,2 s |
| Instalação silenciosa por usuário | OK | 2,2 s |
| Programa instalado, em modo diagnóstico, aberto 3 vezes | OK | 4,19 / 3,02 / 4,04 s |

- O diagnóstico do programa instalado listou os 10 certificados pelo `modPowerShell`, com os acentos corretos. Ele também mostrou a nova próxima ação, "Nenhuma falha encontrada: instalação ativa e certificado pronto", o que confirma que a versão da Fase 3 é a que está instalada.
- A ativação continuou valendo depois da atualização (`LIC-9F1EE9A144F9`), porque a licença fica na pasta da instalação.
- SHA-256 do instalador: `35b8ecd1…7f7221`.

**Teste manual da Fase 3 (24/11/2026, 15:14–15:20, gravação de tela):**
- **Certificados:** a tela abre; exportar de ROOT e adicionar ou excluir em "Pessoas confiáveis" funcionam sem travar. Confirmação do usuário.
- **Gerenciador de usuários:** abre e lista os 8 usuários com o gráfico, sem congelar a janela.
- **Opções → Windows Hello:** a consulta termina e mostra "Não cadastrado.", com "Cadastrar e ativar" habilitado. A mensagem "Verificando…" dura menos de 1 s e quase não aparece. O cadastro do Hello em si não foi testado, porque não era necessário.
- **Observação:** a janela de Opções aparece em gravações, ao contrário do login. Os campos de senha ficam mascarados, mas a proteção é inconsistente. A rever junto com as telas, na Fase 6.

**Situação da Fase 3:** os itens M4, M5, M8 e M9 estão implementados e testados no Windows real e homologados pela interface.

## 12. Fase 4: integração operacional (executada localmente em 24/11/2026)

Feita só na cópia local, sem nenhuma operação remota. A mudança na Corujinha (S7) foi aprovada expressamente pelo usuário.

**Diagnóstico Inteligente S-Cyber (um clique).** O motor fica em `nist_intelligence/diagnostico.py` e a aba "Diagnóstico" em `diagnostico_ui.py`. O fluxo pedido no §11 já existia em partes e foi ligado de ponta a ponta, sem criar um segundo mecanismo:

| Passo do §11 | Onde está |
|---|---|
| Ativo | `garantir_ativo`: o computador vira um ativo "Computador" na primeira execução, com criticidade Média, ajustável |
| Coleta | `collector.run`: 17 verificações somente de leitura, já existentes |
| Evidência | `core.save_collection`: os dados brutos são gravados com SHA-256, e cada achado ganha um instantâneo na cadeia de custódia |
| Achado | `achados.from_collection`: deduplicado por ativo + fonte + verificação; a decisão humana nunca é sobrescrita |
| Risco / prioridade | `diagnostico.prioridade`: regra documentada em `METODOLOGIA_PRIORIDADE` (gravidade + criticidade do ativo + exposição à rede). É uma sugestão; quem confirma o achado define a prioridade final |
| NIST | Subcategorias do CSF 2.0 de cada verificação, todas validadas contra o catálogo |
| Recomendação | `RECOMENDACOES`: uma regra por verificação, com o risco, como corrigir (caminho no Windows ou comando), a permissão necessária, como confirmar e a referência técnica. As referências são citadas por título (Microsoft Learn, CIS, NIST, CISA), sem links não conferidos |
| Correção autorizada | O S-Cyber orienta, mas não altera o computador. A correção é registrada no fluxo de achados, com evidência e revisão |
| Nova verificação | `comparar`: Melhorou / Piorou / Igual / Nova / Sem comparação. Indisponível em uma das duas execuções não conta como melhora |
| Auditoria | `core.audit('Diagnóstico', 'Executar', …)`: cobertura e contagens na trilha encadeada |

**Estados do S-Cyber 2.0:**
- Resultado observado sem falha.
- Suspeita (avaliação pendente), quando o achado está Novo.
- Falso positivo, quando foi descartado com justificativa.
- Achado confirmado.
- Correção registrada.
- Risco tratado, quando o achado foi encerrado.
- Verificação indisponível. Nunca conta como aprovada, não vira achado e fica fora da cobertura ("15 de 16 verificações feitas").

**Interface:**
- Onde está o botão: na Ribbon (NIST Intelligence → "Diagnóstico inteligente"), no menu NIST, no Painel e na aba "Diagnóstico".
- Antes de começar: o escopo precisa ser confirmado.
- Durante a coleta: ela roda numa thread de trabalho, com barra de progresso de 7 etapas e botão de cancelar. Cancelar durante a coleta descarta tudo e não grava nada.
- Banco de dados: só é usado na thread da tela, porque o SQLite pertence a ela.
- Modo básico: mostra o problema, a prioridade, as consequências, a solução, a próxima ação e o resultado da correção.
- Modo avançado: acrescenta a evidência (com o SHA-256), o identificador, as subcategorias NIST com os nomes, o cálculo da prioridade, a metodologia, a referência e o histórico do achado.
- Os dois modos usam os mesmos dados, e o avançado não concede nenhuma permissão a mais.

**Corujinha transparente (S7):**
- **Consentimento:** antes de começar, a Corujinha diz o que vai fazer e pede autorização.
- **Privacidade por padrão:** foto da câmera, captura da tela e internet (raspagem e imagens de páginas) vêm desmarcadas e só rodam se o usuário marcar.
- **Processos identificados:** o andamento mostra o PID de cada processo do PowerShell, igual ao do Gerenciador de Tarefas.
- **Animação visível:** a coruja não se esconde mais das capturas. O relatório continua protegido, porque tem dados sensíveis.
- **Cancelar:** fecha sem executar nada.

**M6 (Corujinha × coletor):** o risco é avaliado por um único motor, o `collector`, com o diagnóstico em cima dele. A Corujinha passa a ser o inventário detalhado opcional, transparente e com consentimento. Levar para o coletor as verificações que só ela tem (persistência, tarefas agendadas, programas sem assinatura, pendrives) fica no backlog, para não aumentar o escopo antes de estabilizar o fluxo principal.

**Testes:**
- `test_fase4.py`, 12 testes: o fluxo do ativo à recomendação, a nova verificação com melhoria, a decisão humana com divergência, o cancelamento sem resto, a regra de prioridade, a recomendação para toda verificação do coletor, o S7 e as ligações da interface.
- A tela simulada executa o diagnóstico (16 linhas), os modos básico e avançado e a reverificação ("4 melhorou, 0 piorou, 12 igual").
- Total: 144 testes OK, 8 pulados.

**Validação no Windows (24/11/2026, 15:35–15:45, script e gravação de tela):**

| Etapa | Resultado |
|---|---|
| Testes automáticos (incluem os do Windows e a consulta real às fontes) | 144 executados, todos OK, em 27,3 s |
| Executável e instalador | 53,6 MB e 54,9 MB |
| Instalação silenciosa | 2,2 s |
| Programa instalado, em modo diagnóstico, aberto 3 vezes | 4,17 / 3,04 / 4,06 s |

- **Diagnóstico real, como usuário comum:** 14 de 17 verificações feitas. Resultado: Falha 0, Atenção 4 (bloqueio de tela, política de senha, portas, logs), OK 10, Indisponível 3, que exigem administrador e não contam como aprovadas. O aviso "executado sem privilégio de Administrador" apareceu.
- **Comparação na reexecução:** "0 melhorou, 0 piorou, 17 igual", correto porque nada foi corrigido entre as duas.
- **Prioridade:** os quatro itens em Atenção, num ativo de criticidade Média, ficaram com prioridade Média, de acordo com a regra documentada.
- **Modo básico:** mostra o problema, a consequência, a solução, a próxima ação, como confirmar e o resultado da correção.
- **Corujinha:**
  - a janela de consentimento abriu antes de tudo, com as três opções desmarcadas por padrão (o usuário marcou as três no teste);
  - a animação apareceu na gravação, com o PID de cada PowerShell (por exemplo, inventário 21068 e disco 25144), igual ao do Gerenciador de Tarefas;
  - o relatório saiu em PDF assinado e protegido por senha.
- **Achado corrigido (local):** o cabeçalho da animação ainda dizia "(protegida contra captura)". Agora diz "trabalhando com a sua autorização (processos e PIDs abaixo)", e um teste impede o texto antigo de voltar.
- **Segunda execução da Corujinha (16:09, programa aberto como administrador, computador sem câmera e sem internet):**
  - Foto da câmera e imagens de páginas apareceram como "--" (não feitas), o que está correto.
  - **Achado:** a raspagem da Wikipédia aparecia como "OK" mesmo sem internet, porque o marcador `web.ok` é gravado sempre. Corrigido localmente: sem autorização, sem internet ou com erro, a raspagem grava `web.falhou` e o andamento mostra "--". Um teste impede a volta.
  - O formulário do relatório não aparece na gravação porque é protegido contra captura (contém dados sensíveis), como previsto.
- **Diagnóstico como administrador (16:14):**
  - **Cobertura:** 17 de 17 verificações feitas, sem nenhuma indisponível.
  - **Resultado:** Falha 1 (BitLocker: disco do sistema sem criptografia; prioridade Média = Falha 3 + criticidade Média 1), Atenção 4 (as mesmas de antes) e OK 12 (Secure Boot, SMBv1, backup, RDP, UAC, firewall e outros).
  - **Ajuste local na tela:** o resumo da comparação agora também mostra "sem comparação" quando a execução anterior teve itens indisponíveis, por exemplo do usuário comum para o administrador. Esses itens não contam como melhora, e um teste confere isso.
- **Situação da Fase 4:** implementada, testada e homologada no Windows real, como usuário comum e como administrador.

## 13. Fase 5 (parte 1): segurança em nuvem, Microsoft Azure (executada localmente em 24/11/2026)

**Provedor escolhido pelo usuário:** Microsoft Azure. A implementação está em `nist_intelligence/nuvem.py` e entra no **mesmo** fluxo do Diagnóstico Inteligente: ativo "Nuvem (assinatura)" → coleta → evidência com SHA-256 → achados → prioridade → NIST → recomendação → nova verificação → auditoria.

| Verificação (§18) | O que é consultado (GET no Azure Resource Manager) | NIST CSF 2.0 |
|---|---|---|
| Exposição pública do armazenamento | `allowBlobPublicAccess`, `publicNetworkAccess` e `networkAcls.defaultAction` das contas de armazenamento | PR.DS-01, PR.AA-05, PR.IR-01 |
| Criptografia | `supportsHttpsTrafficOnly`, `minimumTlsVersion` e `encryption.keySource` | PR.DS-01, PR.DS-02 |
| Configuração de rede | Regras de entrada dos NSGs liberadas para `*`/`Internet`/`0.0.0.0/0` em SSH, RDP, SMB, bancos de dados, WinRM, Telnet e FTP, inclusive em faixas de portas | PR.IR-01, DE.CM-01 |
| Permissões de acesso | Atribuições do papel Owner na assinatura (mais de 3 = Atenção) | PR.AA-05, GV.RR-02 |
| Backup | Cofres do Azure Backup frente às máquinas virtuais | PR.DS-11, RC.RP-03 |
| Registro de eventos | Configurações de diagnóstico que exportam o Log de Atividades | PR.PS-04, DE.CM-03 |

**Acesso e segurança:**
- **Autenticação:** pelo Azure CLI já conectado pelo próprio usuário (`az login`). O S-Cyber usa só `az account show` e `az account get-access-token`.
- **Token:** fica só na memória e nunca vai para a evidência nem para o banco. Um teste confere isso.
- **Permissão:** basta o papel **Leitor (Reader)**. Todas as chamadas são GET, e um teste confere que não há chamadas de escrita.
- **Credenciais:** nenhuma é guardada.
- **Falhas:** um 403 ou outro erro deixa a verificação **Indisponível**, nunca aprovada.

**Demonstração (exigida pelo tema gerador do PI):** o `AMBIENTE_SIMULADO` traz dados **sintéticos** de uma "Empresa Fictícia Ltda", no formato da API, e não usa dados da PMGO. Os achados da demonstração são:
- blob público;
- TLS 1.0;
- RDP aberto à internet;
- 4 proprietários;
- VM sem backup;
- log não exportado.

O ativo recebe o rótulo `[SIMULADO]`, a origem da coleta fica "Nuvem (simulada)" e a tela mostra "DEMONSTRAÇÃO SIMULADA — dados sintéticos" no resumo e em cada item.

**Recomendações:** uma por verificação, com o caminho no Portal do Azure e o comando `az` de correção, executado pelo usuário e não pelo S-Cyber, mais a referência no Microsoft Learn.

**Testes:**
- `test_fase5_nuvem.py`, 9 testes: a avaliação, as faixas de porta, a falha que nunca aprova, a paginação (`nextLink`), o token fora da evidência, o CLI só de leitura e o fluxo com a melhoria comprovada após a correção.
- A tela simulada executa a demonstração (6 de 6 verificações: Falha 3, Atenção 3).
- Total: 154 testes OK.

**Limitações e pendências:**
- **Versões da API:** as versões do Azure Resource Manager (`API` em `nuvem.py`) não puderam ser conferidas daqui, porque este ambiente não tem acesso ao Azure. Uma versão recusada aparece como Indisponível, com o motivo. **Validar com uma assinatura real**, que depende de conta autorizada, somente leitura.
- **Azure CLI:** precisa estar instalado no computador para verificar a assinatura real. A demonstração funciona sem ele e sem internet.

**Validação no Windows (24/11/2026, 16:35–16:41):**
- **Demonstração simulada:** 6 de 6 verificações. Falha 3 (blob público, RDP aberto à internet, VM sem backup) e Atenção 3 (TLS 1.0, log não exportado, 4 proprietários), com prioridades Alta e Média. A faixa "DEMONSTRAÇÃO SIMULADA" aparece no resumo e no detalhe.
- **Sem o Azure CLI:** ao escolher "assinatura real", a mensagem explicou como instalar e entrar com `az login`. Nada foi mostrado como aprovado.
- **Assinatura REAL ("Azure for Students", do Senac):** usada depois de `az login`, só com leitura.
  - **Cobertura:** **6 de 6 verificações feitas, nenhuma indisponível.** Isso confirma que as versões da API do Azure Resource Manager estão aceitas.
  - **Atenção 2:** sem cofre do Azure Backup e Log de Atividades não exportado.
  - **OK 4:** sem armazenamento, 1 proprietário e nenhum grupo de rede exposto.
  - **Comparação:** a segunda execução mostrou "0 melhorou, 0 piorou, 6 igual".
- **Achado corrigido (local):** com 0 contas de armazenamento, o texto da criptografia dizia "Só HTTPS e TLS 1.2", o que afirmava algo que não foi verificado. Agora diz "nada a verificar", e um teste impede a volta do texto antigo.
- **Situação:** a parte de nuvem do §18 está implementada, testada e homologada com assinatura real.

## 14. Regulamento do INOVA 2026 e mudança de prioridade (24/11/2026)

O regulamento foi lido pelo navegador do usuário, já que a leitura automática falhou, na página `programadereconhecimento.dn.senac.br/regulamento`, item 6.1.

- **Categoria:** INOVA, Soluções Inovadoras para o Mercado. É para Projetos Integradores de cursos QP ou HPTNM desenvolvidos entre 01/12/2025 e 30/11/2026.
- **Equipe:** de 2 a 5 alunos mais 1 docente.
- **Pitch:** até 3 minutos, no YouTube, apresentado só pelos alunos.
- **Evidências:** obrigatórias.
- **Critérios:** originalidade 0,30; organização 0,25; adequação ao comércio de bens, serviços e turismo 0,20; viabilidade 0,15; resultados 0,10.
- **Desclassificação:** inclui descumprir a LGPD.
- **Prazo da equipe junto ao Regional: 30/11/2026.**
- **Decisões do usuário:**
  - inscrever o projeto nesta edição, pelo professor;
  - homologar só o Windows;
  - autorizar as Fases 6, 7, 5b e 9 e a publicação no GitHub, que fica para o fim.
- **Consequência:**
  - o material do INOVA (proposta, roteiro do pitch, evidências) foi feito antes das demais fases, no documento "S-Cyber Business — Proposta INOVA 2026";
  - o INOVA concorre com a modalidade **Business**, para PMEs do comércio, e não com a PM.

## 15. Fase 7 (parte 1): modalidades PM e Business (executada localmente em 24/11/2026)

- **Objetivo:** um só código-fonte, com a modalidade decidida pela licença assinada, sem configuração que o usuário possa trocar sozinho.
- **Arquivos:**
  - `modLicenca.py`: `MODALIDADES`, `EXCLUSIVO_PM = ("sei",)`, `modalidade()`, `nome_produto()`, `recurso_liberado()`;
  - `admin_licencas.py`: `--modalidade {pm,business}`; a renovação e a transferência mantêm a modalidade;
  - `appSCyberPM.py`: título e fundo mudam conforme a modalidade, e `abrir_sei` só roda quando o recurso está liberado.
- **Decisões:**
  - licença antiga, sem o campo, continua valendo como `pm`, então nada quebra para quem já está ativado;
  - o bloqueio do SEI é feito na regra de negócio, não só no botão.
- **Testes:** `test_ativacao.py` cobre a emissão Business, a recusa do SEI e o nome do produto.
- **Situação:** implementado e testado automaticamente, mas **não homologado** no Windows com uma licença Business real.

## 16. Publicação no GitHub (24/11/2026, autorizada expressamente pelo autor)

- **Autorização do autor:** "salve e organize tudo no github agora, deixando as instruções de instalação".
- **Nenhum repositório foi apagado nem criado.** Tudo foi para o repositório existente.
- **Como foi publicado:**
  - os commits da cópia local foram para o branch `s-cyber-2.0`;
  - o PR #11 passou pelo CI (testes e geração do instalador no `windows-latest`) antes do merge na `main`;
  - o envio da tag `v2.0.0-beta.1` a partir desta sessão foi **recusado com HTTP 403**, porque a política da sessão reserva a publicação de versões ao autor. A recusa não foi contornada;
  - o PR #12 fez o workflow aceitar Releases criadas pelo site (`release: published`): o autor publica a Release e o CI anexa o mesmo instalador testado, com o `SHA256SUMS.txt`;
  - **pendente, ação do autor:** criar a Release `v2.0.0-beta.1` (pré-lançamento) sobre a `main`.
- **Listas assinadas publicadas** em `S-Cyber-PM-Integrado/licencas/` (administradores, credenciamentos, revogações e registro):
  - assinatura conferida antes de publicar e válidas até **24/12/2026**;
  - precisam ser reassinadas e republicadas antes dessa data, senão o aplicativo passa a usar só o cache.
- **Conferência de segurança antes do envio:**
  - nenhuma chave privada (`.key`, `.pfx`, `.p12`, `.pem` com `PRIVATE KEY`);
  - nenhum banco `.db` e nenhum token no conteúdo enviado.
- **Limitação:** o instalador não tem assinatura de código, então o Windows SmartScreen mostra "Editor desconhecido". A integridade é conferida pelo hash SHA-256 publicado.

## 17. Fases 5 (parte 2) e 7 (parte 2): inteligência e clientes reais (executadas localmente em 25/11/2026)

Feitas sem mexer na interface, porque o pitch do INOVA ainda vai ser gravado.

| Item | O que mudou | Prova automatizada | Situação |
|---|---|---|---|
| Retentativa nas fontes | `fontes.http_get` e o novo `http_post_json` repetem só as falhas passageiras (5xx e rede), com espera de 1 s e 2 s. Acesso recusado e limite de consultas não são repetidos. A conexão do `HTTPError` é fechada, o que elimina o `ResourceWarning` visto em 24/11 | `test_achados.FontesTests` (contagem de tentativas e esperas; recuperação depois de um 502), suíte rodada com `-W error::ResourceWarning` | Implementado e testado |
| E-mail do domínio | Novo `nist_intelligence/dominio.py`. Lê o DNS público (Google Public DNS, DNS sobre HTTPS) pelo `fontes.http_get` e avalia SPF, DMARC e DNSSEC. O resultado entra no **mesmo fluxo** do diagnóstico (`registrar(..., dominio=True)`): ativo "Domínio/Serviço web", evidência, achados, prioridade (SPF e DMARC contam como expostos), NIST (PR.AA-03, PR.PS-01, DE.CM-01, PR.DS-02), recomendação, nova verificação e auditoria. Falha de rede e domínio inexistente aparecem como Indisponível, nunca aprovados | `test_fase5b.py`: 9 testes, incluindo a melhoria comprovada "3 melhorou" e a consulta real no CI | Implementado e testado. **Na tela só depois do pitch**; por enquanto roda por `python -m nist_intelligence.dominio empresa.com.br` |
| OSV.dev | `fontes.osv_pacotes` (consulta em lote; só nome, ecossistema e versão saem do computador) e `nist_intelligence/dependencias.py`. O CI confere o `requirements-lock.txt` a cada execução e mostra o resultado no resumo, de forma **informativa** por enquanto | `test_fase5b.OsvTests` + consulta real no CI | Implementado e testado |
| Vencimento das listas de licença | `modLicenca.situacao_listas` e `aviso_listas`. O diagnóstico do aplicativo mostra a validade e avisa a partir de 10 dias; `admin_licencas verificar` mostra `AVISO`; o novo workflow diário *Validade das listas de licença* falha a partir de 10 dias, e o GitHub avisa por e-mail. O texto "Publique" agora diz se é obrigatório (listas) ou opcional (registro) e avisa quando a pasta veio de um ZIP, a confusão vista em 25/11 | `test_ativacao.VencimentoDasListasTests` | Implementado e testado |
| Dados separados por empresa | A licença Business leva `organizacao` (`emitir --organizacao`; renovar e transferir mantêm). Na abertura, **antes de abrir qualquer dado**, o aplicativo define a pasta da empresa (`%APPDATA%\SCyberPM\perfis\<empresa>`), mesmo com a licença vencida, para a recuperação achar a pasta certa. O banco NIST (`core.DB`) passou a ser resolvido a cada uso. A licença PM não tem organização: a pasta continua a de sempre. Nomes de pasta seguros no Windows (sem acentos e sem CON, NUL…) | `test_ativacao.OrganizacaoTests`: 5 testes, incluindo licença adulterada ou de outro computador, que não escolhe pasta | Implementado e testado; **não homologado no Windows** |

**Testes:** 180 executados, todos OK, 10 pulados (Windows, tkinter ou consulta real). O lint do CI ficou limpo, e a tela simulada repete as Fases 4 e 5.

**Pendências registradas:**
- Na modalidade Business, os certificados fixos da PMGO ainda são aceitos na abertura. Restringir a autenticação muda o login e fica para a Fase 7, junto com a autoridade certificadora privada que vai emitir os certificados das empresas.
- Os módulos de treinamento (rádio, ponta a ponta, memória, disco e processador) continuam visíveis na Business. Ficam para a Fase 6 (área "Treinamento").
- A verificação do domínio ganha botão na aba Diagnóstico na Fase 6.

## 18. Tela do administrador: ativação sem PowerShell (25/11/2026, a pedido do autor)

**Problema relatado:** para ativar um computador novo, o administrador precisava:
- rodar um comando longo no PowerShell, numa pasta de caminho longo;
- colar um pedido que chegava quebrado em várias linhas;
- levar o arquivo `.sclic` de volta;
- e ainda interpretava "Publique: git…" como obrigatório.

**Solução escolhida pelo autor:** a tela do administrador (`admin_licencas_tela.py`, aberta com dois cliques em `Administrar licencas.bat`).
- **O que a tela faz:**
  - reconhece o tipo de pedido colado (ativação ou certificado), mesmo com quebras de linha;
  - emite a licença PM ou Business, já com a empresa;
  - deixa a **chave copiada** para voltar por WhatsApp ou e-mail, sem arquivo;
  - credencia certificados;
  - mostra a validade das listas e as renova;
  - envia ao GitHub só a pasta `licencas`.
- **O que não muda:** é a mesma `admin_licencas.Admin` da linha de comando, com o mesmo certificado e as mesmas regras. Nenhuma lógica nova de emissão.
- **Segurança:** como a linha de comando, a tela **não vai no instalador**. O `gerarExe.py` exclui `admin_licencas` e `admin_licencas_tela`, e um teste impede que o aplicativo importe esses módulos. O aplicativo instalado continua recusando qualquer documento não assinado por um administrador.
- **Testes:** `tests/test_admin_tela.py` (resumo do pedido, envio ao GitHub com Git simulado, exclusão do executável e atalho). A tela real é testada no Windows do CI: colar, emitir como Business, a chave copiada ativar a instalação, credenciar como revisor. Também foi exercitada no simulador de interface.
- **Situação:** implementado e testado. A homologação pelo autor no Windows dele está pendente.

## 19. Pedido por e-mail com um clique (25/11/2026, escolha do autor)

**Motivo:** mandar o pedido e a chave pelo WhatsApp não deixa registro formal, mistura com conversas pessoais e não escala para clientes.

**O autor avaliou três caminhos** e escolheu o primeiro para agora:
1. e-mail com um clique (escolhido);
2. formulário online;
3. portal de ativação automática, que fica para a versão comercial, depois do INOVA.

**Como ficou o e-mail:**
- **Endereço:** `scybersuporte@gmail.com`, num lugar só (`modLicenca.EMAIL_SUPORTE`). Um teste impede o endereço de se repetir no código.
- **Na tela de ativação e na do certificado**, o botão **Enviar pedido por e-mail**:
  - abre o e-mail pronto (`mailto:`), com assunto padrão, campos de nome, unidade ou empresa e telefone, e o pedido;
  - **também copia o e-mail inteiro**, para quem usa e-mail só no navegador, onde o `mailto:` não abre nada.
  - "Copiar pedido" continua disponível.
- **Na tela do administrador:** depois de emitir, fica copiada uma **resposta pronta** (instruções + chave) para responder ao e-mail.
- **Dados:** o pedido não é segredo. Identifica a instalação ou o certificado, o computador e a conta do Windows; nome e telefone, quem preenche é a pessoa.

**Testes:** `test_admin_tela.EmailTests`:
- assunto e corpo;
- `mailto:` com menos de 2.000 caracteres;
- o pedido recuperado do corpo é reconhecido;
- a chave da resposta pronta ativa a instalação;
- o endereço aparece num lugar só.

A tela real no Windows do CI confere a resposta copiada.

**Conta de suporte:** criada pelo autor em 25/11/2026, com acesso confirmado. As orientações de proteção (verificação em duas etapas, recuperação, delegação em vez de senha compartilhada, filtro dos pedidos, alerta de golpe) e o teste de ponta a ponta estão em `docs/ADMINISTRACAO_LICENCAS.md`. O teste de ponta a ponta pelo autor está **pendente**.

**Roadmap:** o README ganhou a seção "Roadmap (planejado, ainda não disponível)", que separa o que está pronto do que ainda vai ser feito:
- ativação online automática, para a versão comercial da Business;
- IA aberta e local, opcional;
- dois instaladores, ainda em avaliação;
- Fases 6 a 8.

## 20. Testes em máquina limpa: Windows Sandbox e VirtualBox (25/11/2026, pelo autor)

O autor reinstalou tudo do zero. O computador dele ficou como administrador e certificador. O usuário final foi testado primeiro na Windows Sandbox e depois numa máquina virtual Windows 10 (VirtualBox), com gravações de tela.

**Funcionou de ponta a ponta:**
- instalação pela Release, com conferência do SHA-256;
- pedido de ativação por e-mail;
- emissão da licença Business pela tela do administrador e resposta pronta;
- ativação;
- certificado criado e pedido de credenciamento;
- credenciamento e publicação automática no GitHub (23:37);
- renovação das listas (23:43).

**Problemas que só um Windows novo revelou, todos corrigidos:**

| Visto | Causa | Correção |
|---|---|---|
| "Não foi possível listar os certificados: #< CLIXML … Preparing modules for first use" (Sandbox) | A primeira execução do PowerShell escreve uma barra de progresso no stderr, em CLIXML | `$ProgressPreference = 'SilentlyContinue'` em todo script; o stderr em CLIXML vira só o texto dos erros reais (`modPowerShell.limpar_erro`) |
| Certificado credenciado, mas a máquina virtual não via o credenciamento. O diagnóstico mostrou `[SSL: CERTIFICATE_VERIFY_FAILED] unable to get local issuer certificate`, e as listas vinham do pacote | O Windows novo só baixa as raízes TLS quando um programa dele precisa; o Python não pede | Novo `modRede`: as raízes do Windows **somadas** às do `certifi`, com a verificação completa mantida. Vale para as listas de licença e para todas as fontes de inteligência |
| A tela do administrador não abria, sem mensagem | O `pythonw` não tem console | O atalho confere antes com o `python.exe`; erros viram mensagem e ficam em `admin_tela_erro.log` |
| Envio recusado e depois "cannot do a partial commit during a merge" | Duas pastas de administração e um `git pull` com conflito que parou no meio | A tela sincroniza ao abrir, junta e reenvia sozinha (`registro.jsonl` com `merge=union`) e reconhece junção ou rebase pela metade |
| `NOVA_IMPRESSAO` na lista de administradores | Um texto de exemplo de uma resposta foi executado como comando; a ferramenta aceitava qualquer texto | Só aceita 40 caracteres hexadecimais; a entrada foi removida pelo autor (publicação de 20:03); inofensiva enquanto existiu |
| Teste das coletas falhando depois das 21h | `run_at` em UTC comparado com a data local | A data é convertida para a hora local antes de comparar |

**Versão:** 2.0.2, que junta as correções do lado do usuário final (PowerShell e TLS).

**Confirmação na prática (26/11/2026, 00h20–00h45, gravação do autor):** a 2.0.2, instalada pela Release na máquina virtual, aceitou o certificado AF625100… poucos minutos depois do credenciamento. Esse certificado só existe na lista publicada no GitHub, então as listas foram baixadas da internet: a correção do TLS funcionou. O mesmo teste cobriu o primeiro acesso (senhas fortes) e o Diagnóstico Inteligente: 14 de 17 verificações feitas (9 OK, 4 em atenção, 1 falha e 3 indisponíveis por falta de privilégio de administrador, sem contar como aprovadas).

## 21. Versão 2.0.3: ajustes vistos no teste da máquina virtual (26/11/2026)

| Visto no teste | Correção |
|---|---|
| "Conexão SEI: desconectada" no cabeçalho do S-Cyber **Business** | A modalidade vem da licença assinada até o painel NIST (`sei`, `produto`). Na Business somem: a aba Consultas SEI, o SEI no cabeçalho, a coluna e o botão do processo SEI nos incidentes, a coluna SEI do relatório em PDF, o item do menu, o botão da Ribbon, o atalho Ctrl+I, o comando do assistente e os 2 passos do Tour. A PM continua igual |
| O painel mostrava "v1.3.0" (versão interna do módulo NIST) e o instalador, 2.0.2 | Versão única no novo `versao.py`, usada pelo `formAbout`, pelo instalador, pelo executável e pelo painel |
| Abas cortadas ("Pain", "Diagnósti") em telas menores | As abas do painel quebram em várias linhas conforme a largura (`_BarraDeAbas`); o Notebook continua controlando as abas, e Ctrl+Tab passou a trocar de aba |
| Certificado ainda "não autorizado" logo depois do credenciamento | Era o atraso de até 5 minutos do GitHub; as mensagens do usuário e do administrador agora avisam isso |
| Textos do painel citavam "S-Cyber PM" também na Business | Passam a dizer "S-Cyber"; as consultas às fontes públicas deixaram de enviar "PMGO" no User-Agent |

**Testes:** 218 no Linux (17 pulados, os de janela e os exclusivos do Windows), com 11 novos em `tests/test_v203.py`. Os testes de janela (Business sem SEI, abas em várias linhas, Tour) rodam no CI do Windows.

**Ainda não feito:** a identidade visual da Business (nome na abertura, no Tour e nos textos da janela principal) continua com "S-Cyber PM" em vários pontos. Isso fica para a Fase 6, junto com as 5 áreas.

## 22. Revisão de segurança das licenças (26/11/2026)

Achados de uma revisão externa do código, conferidos um a um no código da 2.0.3 antes de corrigir.

| Gravidade | Achado | Confirmado? | Correção | Prova |
|---|---|---|---|---|
| Alta | A lista de administradores era aceita sem conferir a validade; uma cópia antiga, ainda assinada, continuava autorizando um administrador removido | Sim (`Publicacao.administradores`) | Só vale a lista **vigente**; sem ela, só os administradores fixos do programa. **Anti-retorno** para as três listas: cada computador guarda a maior sequência aceita (`sequencias_vistas.json`) e recusa cópias com sequência menor. O diagnóstico mostra as cópias recusadas | `test_revisao_licencas.ListaDeAdministradoresTests` (lista vencida, cópia antiga reposta, revogação que não pode ser desfeita) |
| Média | A data de validade do certificado do administrador era devolvida, mas não usada | Sim (`modLicenca.abrir`) | A data da assinatura (signingTime) precisa estar dentro da validade do certificado; a validade do documento não pode passar de 31 dias (listas) ou 1.100 dias (licenças) contados da assinatura. Isso limita o estrago de uma chave antiga vazada que "volte a data" da assinatura. A ferramenta do administrador recusa licenças acima de 1.100 dias | `test_revisao_licencas.ValidadeDoCertificadoTests`, incluindo as listas reais publicadas |
| Média | A busca da raiz do Git subia até qualquer pasta acima; uma pasta de ZIP dentro de outro repositório era tratada como clone | Sim (`admin_licencas.raiz_git`) | Vale o repositório mais próximo, e só se a pasta das listas estiver em `S-Cyber-PM-Integrado/licencas` e o `origin` for `gsilveiralima/S-Cyber-PM-Integrado-NIST-2.0` (https, ssh e worktree). A mensagem diz o motivo | `test_admin_tela.RepositorioCertoTests` |
| Baixa | O Explorer era aberto com o caminho montado dentro de um texto | Sim (`formHash.abrir_pasta`) | Argumentos em lista, como já fazia a Pesquisa de arquivos | Revisão do código (só Windows) |

**Efeito colateral aceito:** um computador que só tenha uma cópia recusada (antiga ou vencida) de uma lista para de validar licenças até baixar a atual, em vez de aceitar a cópia antiga. A mensagem explica o motivo.

**Cuidado operacional novo:** nunca recriar as listas do zero, porque a sequência voltaria a 1 e seria recusada.

**Testes:** 233 no Linux, todos OK (17 pulados).

## 23. Versão 2.0.4: PowerShell não encontrado num computador corporativo (26/11/2026)

**Relato do autor (teste real, 13:26):** num computador corporativo, conta `defesa.cibernetica`, licença Business ativa e listas online, a tela do certificado mostrava "Certificados: não foi possível listar (PowerShell não encontrado.)". A próxima ação dizia, errado, "Nenhum certificado nesta conta".

| Causa | Correção | Prova |
|---|---|---|
| O S-Cyber chamava `powershell` pelo nome e dependia da PATH; nesse computador a PATH não tinha `WindowsPowerShell\v1.0` | `modPowerShell.executavel()`: caminho completo em `%SystemRoot%\System32\WindowsPowerShell\v1.0`, depois `Sysnative` (programa de 32 bits), só então a PATH. Vale para todo o programa e para a Corujinha | `test_powershell_caminho.CaminhoCompletoTests`; no CI do Windows, os testes reais de assinatura e do coletor usam o caminho novo |
| Mensagens genéricas | Mensagens com causa e solução: PowerShell ausente, bloqueado pela política (AppLocker/GPO, erros 5 e 1260) e modo restrito (ConstrainedLanguage) | `test_powershell_caminho.MensagensTests` |
| Diagnóstico confundia "não consegui listar" com "não há certificado" | Situação nova `indisponivel`, com próxima ação própria | `test_powershell_caminho.DiagnosticoTests` |

A 2.0.4 também leva aos clientes as correções da seção 22 (validade e anti-retorno das listas, validade do certificado do administrador).

## 24. Próximo passo proposto
1. **Validar no Windows** (script de sempre, `validar_no_windows.ps1`):
   - testes, instalador e abertura da versão nova;
   - uma licença Business com `--organizacao`: os dados vão para `perfis\<empresa>`, e a instalação PM continua com os dados de sempre;
   - `python -m nist_intelligence.dominio <domínio da empresa>`.
2. **Fechar o produto mínimo (§27), testes do usuário:**
   - registrar a correção pela tela;
   - demonstrar "1 melhorou";
   - fazer backup e restauração pela tela;
   - instalar numa máquina limpa.
3. **Depois do pitch:**
   - Fase 6 (5 áreas, assistente de primeiro acesso, indicadores históricos, botão do domínio);
   - Fase 7 (autoridade certificadora privada, autenticação da Business, duas assinaturas para remover administrador, pontos de verificação assinados);
   - Fase 8 (assinatura de código e atualização segura);
   - Fase 9 (homologação final).
