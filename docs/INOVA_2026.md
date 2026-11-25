# S-Cyber Business — Proposta INOVA 2026

Projeto Integrador do curso **Técnico em Defesa Cibernética** do
[Centro de Educação Profissional Senac Cora Coralina](https://www.go.senac.br/unidades/centro-de-educacao-profissional-cora-coralina/)
(Goiânia – GO), turma em parceria com a Polícia Militar do Estado de Goiás, inscrito na categoria
**INOVA – Soluções Inovadoras para o Mercado** do Prêmio Atena 2026 (Programa de Reconhecimento Senac).

> **Versão pública.** Os números de matrícula, o link interno do formulário de inscrição e os dados de
> contato ficam **fora** do repositório, por proteção de dados (LGPD). Eles estão só no documento de
> trabalho da equipe e serão informados no formulário oficial e no relatório do docente.

## Equipe

| Função | Nome |
|---|---|
| Aluno | Leonídio Alves De Moraes Junior |
| Aluno | Daniel Otavio De Lima Medrado |
| Aluno | Juliano Porto De Souza |
| Aluno | Juliano Santos Borges |
| Aluno | Gabriel Silveira Lima |
| Docente responsável pela UC Projeto Integrador | Fabiana Fernandes Harami |

A equipe tem **5 alunos**, o máximo permitido pelo regulamento, e **1 docente**.

## Prazos

| Data | Etapa |
|---|---|
| 30/11/2026 | Prazo final de inscrição da equipe no Senac Goiás |
| 18/12/2026 | O Senac Goiás envia ao Nacional até **3 projetos** selecionados |
| 22/01/2027 | Avaliação da banca nacional |
| 29/01/2027 | Aviso aos finalistas |
| Março de 2027 | Cerimônia de premiação |

O pitch em vídeo é obrigatório para a **etapa nacional**. A equipe confirma com o docente se o link já vai
na inscrição de 30/11 ou só depois da seleção regional.

## Condições de participação

- Projeto desenvolvido num curso de Qualificação Profissional (QP) ou Habilitação Profissional Técnica de
  Nível Médio (HPTNM), na Unidade Curricular Projeto Integrador, entre **01/12/2025 e 30/11/2026**.
- Equipe de **2 a 5 alunos** com matrícula ativa durante o desenvolvimento, mais **1 docente** com vínculo
  com o Senac.
- Um projeto por equipe; o docente pode orientar mais de uma.
- Pitch de **até 3 minutos**, feito e apresentado **só pelos alunos**, publicado no YouTube.
- Desclassificam: pitch acima de 3 minutos ou apresentado por quem não é da equipe; equipe fora do
  tamanho ou sem docente; falta de evidência do período e da matrícula; cadastro fora do formulário ou do
  prazo; descumprimento da LGPD.

Fontes: documento "INOVA – Condições de participação" do Senac Goiás e
[regulamento do Programa de Reconhecimento Senac](https://programadereconhecimento.dn.senac.br/regulamento/),
item 6.1. Dúvidas sobre o edital: categoriainova@senac.br.

## Problema e solução

**Problema.** A pequena loja, a agência de turismo ou o escritório de serviços guardam dados de clientes,
pagamentos e documentos em computadores e na nuvem, mas raramente têm um especialista em segurança.
Ferramentas profissionais de diagnóstico são caras, exigem conhecimento técnico e entregam relatórios que o
dono do negócio não sabe transformar em ação.

**Solução: S-Cyber Business.** Um aplicativo para Windows que:

1. **Verifica em um clique** o computador (17 itens: antivírus, firewall, criptografia do disco,
   atualizações, contas, senhas, portas abertas, backup e outros) e, opcionalmente, a nuvem Microsoft Azure
   (6 itens), **somente lendo**, sem alterar nada.
2. **Explica cada problema em linguagem simples:** o que foi encontrado, por que é um risco, como corrigir
   passo a passo e como confirmar a correção.
3. **Prioriza** pelo risco real, com regra documentada (gravidade + importância do equipamento + exposição
   à internet).
4. **Comprova a melhoria:** depois de corrigir, a nova verificação compara com a anterior e mostra o que
   melhorou.
5. **Organiza tudo pelo NIST CSF 2.0**, a referência internacional de gestão de riscos cibernéticos, com
   evidências protegidas por SHA-256 e trilha de auditoria.

**Para quem:** empresas do comércio de bens, serviços e turismo sem equipe de TI. O mesmo núcleo também
atende a uma modalidade institucional (S-Cyber PM), que não faz parte desta inscrição.

## A proposta pelos 5 critérios da banca

Os números abaixo foram medidos no Windows 11 da equipe em 24/11/2026; nada é estimativa.

| Critério | Peso | Nosso argumento, com evidência |
|---|---|---|
| Originalidade e criatividade | 30% | Diagnóstico que fecha o ciclo inteiro: encontra, explica em linguagem simples, prioriza e **comprova a melhoria** na nova verificação. Liga cada achado ao NIST CSF 2.0 sem exigir conhecimento técnico. Um clique, sem terminal |
| Organização e clareza | 25% | Objetivo: reduzir riscos cibernéticos de PMEs. Procedimento: instalar, ativar, diagnosticar, corrigir, verificar de novo. Apuração: comparação automática entre diagnósticos e trilha de auditoria |
| Adequação e relevância | 20% | No computador real da equipe, o diagnóstico achou **1 falha** (disco sem criptografia) e **4 pontos de atenção** (bloqueio de tela, política de senha, portas abertas, registro de eventos). Na nuvem Azure real, **2 pontos de atenção** (sem backup, log não exportado). Ajuda a cumprir a LGPD ao proteger dados de clientes |
| Viabilidade e razoabilidade | 15% | Instalador de **54,9 MB**, instalação em **2,2 s** sem administrador, abertura em **3 a 4 s**. Funciona sem internet. Não exige servidor nem assinatura paga para o núcleo. Testes automatizados passando no Windows e no CI |
| Expectativa de resultados | 10% | Indicador proposto: **% de itens com problema que melhoraram** entre o 1º e o 2º diagnóstico de cada empresa, medido pelo próprio programa. Na demonstração simulada de nuvem, 4 dos 6 itens melhoraram após as correções |

Nota final da banca: `0,30·I01 + 0,25·I02 + 0,20·I03 + 0,15·I04 + 0,10·I05`.

**Ponto fraco conhecido:** o critério 5 pede percentuais de resultado em empresas. Sem um piloto com uma
empresa real autorizada, a equipe apresenta o método de medição e o resultado no próprio computador, sem
inventar percentuais de redução de custo.

## Checklist oficial de envio

Situação em 25/11/2026.

| Item | Situação | O que falta |
|---|---|---|
| **1. Identificação** | | |
| Título do Projeto Integrador | Proposto | "S-Cyber Business: diagnóstico de segurança cibernética em um clique para pequenas e médias empresas". Confirmar com o docente |
| Unidade educacional e curso | Pronto | Centro de Educação Profissional Senac Cora Coralina, Goiânia – GO. Técnico em Defesa Cibernética, turma em parceria com a PMGO |
| Alunos participantes | Pronto | Tabela "Equipe" |
| Docente responsável | Pronto | Fabiana Fernandes Harami |
| Comprovação da matrícula | Pronto | Para esta turma basta o número da matrícula, informado no formulário (confirmado com a docente e a secretaria em 25/11/2026) |
| Período de desenvolvimento | Falta confirmar | Datas da turma e do PI, dentro de 01/12/2025 a 30/11/2026 |
| **2. Descrição da proposta** | | |
| Problema, solução, objetivos, procedimentos, originalidade | Pronto | Seções acima e [relatório de auditoria](AUDITORIA_S-CYBER_2.0.md) |
| Viabilidade econômica, técnica e operacional | Parcial | Falta o custo estimado de implantação e manutenção |
| Impactos econômicos, tecnológicos e socioambientais | Parcial | Falta escrever o impacto socioambiental (proteção de dados de clientes e acesso à segurança para quem não pode pagar um especialista) |
| Resultados alcançados ou esperados | Pronto | Resultados medidos no Windows e no Azure da equipe |
| **3. Documentação e evidências** | | |
| Relatório do docente | Adiado | Não é necessário por enquanto (decisão da equipe, 25/11/2026). Modelo abaixo |
| Fotos ou vídeos | **Falta** | Fotos datadas da equipe trabalhando |
| Participação dos alunos e do docente | Adiado | Não é necessário por enquanto (decisão da equipe, 25/11/2026). Se for pedido, cada aluno precisa de evidência própria |
| Entregas parciais e consolidação | Parcial | Commits datados e relatório de auditoria; falta a confirmação do docente |
| Desenvolvimento dentro da UC Projeto Integrador | Adiado | Comprovado pelo relatório da docente, adiado junto com ele |
| **4. Vídeo pitch** | Falta gravar | Roteiro abaixo |

## Roteiro do pitch (até 3 minutos)

Duração de cerca de **2 min 40 s**, com 20 s de folga. Um bloco para cada um dos 5 alunos; o Aluno 1 abre
e fecha. O docente **não** pode aparecer falando.

| Tempo | Quem | Fala | Na tela |
|---|---|---|---|
| 0:00–0:20 | Aluno 1 | "Uma loja pequena guarda dados de clientes e pagamentos, mas não tem especialista em segurança. Um ataque pode parar o negócio e gerar multa da LGPD. Nós somos alunos do curso Técnico em Defesa Cibernética do Senac e criamos o S-Cyber Business." | Alunos de frente para a câmera |
| 0:20–0:45 | Aluno 2 | "O S-Cyber faz um diagnóstico de segurança em um clique. Ele só lê as configurações, não altera nada, e funciona sem internet." | Clique em **Diagnóstico inteligente** e a barra de progresso |
| 0:45–1:20 | Aluno 3 | "Em segundos ele verificou 17 itens deste computador. Achou o disco sem criptografia e quatro pontos de atenção. Para cada um, explica o risco em linguagem simples, mostra como corrigir e como confirmar." | Resultado real: tabela com prioridades e o detalhe do **bloqueio de tela** |
| 1:20–1:50 | Aluno 4 | "Seguimos a recomendação e configuramos o bloqueio de tela. Na nova verificação, o S-Cyber comprova: um item melhorou. Tudo fica registrado na auditoria." | Correção feita e a nova verificação com **"1 melhorou"** |
| 1:50–2:15 | Aluno 5 | "Ele também verifica a nuvem Microsoft Azure: armazenamento público, portas abertas, backup e registros. E organiza tudo pelo NIST CSF 2.0, referência internacional em segurança." | Demonstração de nuvem com a faixa **DEMONSTRAÇÃO SIMULADA** visível |
| 2:15–2:40 | Aluno 1 | "É viável: instalador de 55 MB, instalação em segundos, sem servidor nem assinatura. O dono do negócio sabe o que corrigir e comprova a melhoria. S-Cyber: segurança que se entende e se comprova." | Alunos de frente para a câmera e o logotipo da coruja |

**Cuidados na gravação:**
- Gravem com o S-Cyber já instalado e ativado; as telas de senha não aparecem na gravação, por proteção.
- Corrijam o bloqueio de tela **de verdade** e rodem o diagnóstico de novo: o "1 melhorou" precisa ser real.
- Não mostrem nome de usuário, número da assinatura Azure, endereço IP, matrículas ou dados do Senac. Na
  nuvem, usem só a demonstração simulada.
- Cronometrem o vídeo final.

## Evidências e modelo do relatório do docente

| Evidência | Onde está | Quem providencia |
|---|---|---|
| Relatório do docente | A preencher | Docente do Projeto Integrador |
| Fotos ou vídeos das entregas parciais | Celulares da equipe | Equipe |
| Histórico de versões (commits datados) | Este repositório | Equipe |
| Relatório de auditoria técnica com fases e medições | [AUDITORIA_S-CYBER_2.0.md](AUDITORIA_S-CYBER_2.0.md) | Equipe |
| Resultados da validação no Windows | Arquivos `RESULTADO.txt` gerados por `validar_no_windows.ps1` | Equipe |
| Link do pitch no YouTube | Formulário de inscrição | Equipe |

Modelo do relatório (usar o modelo oficial se o Regional fornecer):

1. Curso, turma, unidade Senac e período do Projeto Integrador.
2. Docente responsável e alunos da equipe, com matrícula.
3. Desafio real do setor produtivo: segurança cibernética de pequenas e médias empresas do comércio.
4. Entregas parciais com datas: auditoria do código, diagnóstico em um clique, verificação de nuvem, testes
   no Windows.
5. Competências aplicadas: fundamentos de defesa cibernética, redes, programação em Python, criptografia e
   segurança em nuvem.
6. Fotos ou vídeos de cada entrega, com data.
7. Resultados medidos (seção "A proposta pelos 5 critérios da banca").
8. Assinatura do docente e data.
