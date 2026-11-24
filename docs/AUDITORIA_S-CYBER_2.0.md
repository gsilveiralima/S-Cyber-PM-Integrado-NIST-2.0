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

## 11. Próximo passo proposto
1. Fazer o teste manual da interface (itens 1 a 4 do RESULTADO.txt) para fechar a Fase 2.
2. Fase 3, refatoração estrutural (só local):
   - unificar os executores de PowerShell (M4) e as pastas de dados (M5);
   - tirar da interface as chamadas que a travam (M8);
   - remover o código morto (M9) depois da aprovação.
