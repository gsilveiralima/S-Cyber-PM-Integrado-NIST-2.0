# S-Cyber PM 1.6 / NIST Intelligence 1.3.0 — Windows completo

## Primeira abertura, diagnóstico e troca de certificado
- **Ordem da abertura:** ativação da instalação → certificado do policial → dados cifrados (opções e
  banco NIST). Quando uma etapa falha, o programa não encerra mais. A tela de abertura mostra:
  - a etapa que falhou;
  - o diagnóstico (que pode ser copiado ou salvo);
  - a próxima ação.
- **Diagnóstico** (`SCyberPM.exe --diagnostico`, também como atalho no menu Iniciar). Mostra:
  - a versão em execução, o caminho do programa, a pasta de dados e a conta do Windows;
  - os certificados de `Cert:\CurrentUser\My`, distinguindo os casos:
    - certificado ausente;
    - autorizado, mas sem a chave privada (só o `.cer` importado);
    - vencido;
    - não autorizado;
    - chave que não é RSA;
  - a ativação e a origem das listas publicadas;
  - cada arquivo cifrado do perfil, com qual certificado o abre.
- **Assistente de perfil.** Trata em conjunto os arquivos cifrados do perfil:
  - `scyber_pm.opcoes`;
  - `nist\nist.db`;
  - os arquivos `*.antigo`, os backups e a pasta `arquivo\`.

  Quando o certificado antigo continua acessível nesta conta, a migração segue esta ordem:
  1. copia e recifra os dados;
  2. confere registro a registro, com os textos decifrados;
  3. confere as cadeias de hash;
  4. testa a restauração;
  5. só então troca os arquivos ativos. Os originais vão para `arquivo\<data>_…` com um LEIA-ME.

  Sem a chave antiga, nada é apagado: um perfil novo só é criado se o usuário digitar `NOVO PERFIL`.
- **Duas cópias do programa no mesmo perfil:** o programa avisa, com o caminho e a versão da outra cópia.
- **Execução pelo PowerShell 7:** a variável `PSModulePath` é removida, para os subprocessos do
  PowerShell 5.1 funcionarem.

## Ativação sob controle dos administradores
- Cada instalação tem um id e a impressão da máquina. A licença:
  - é **assinada no Windows do SGT Gabriel ou do MAJ Leonídio** (CMS/SHA-256, chave não exportável);
  - tem validade definida;
  - é vinculada à instalação.
- Listas **assinadas** e publicadas em `S-Cyber-PM-Integrado/licencas/` no GitHub:
  - administradores;
  - revogações;
  - credenciamentos.

  O aplicativo confere a assinatura e quem assinou. Ele usa a lista de maior sequência e guarda uma
  cópia local. Uma revogação vale na próxima abertura com internet, ou em até 30 dias sem ela.
- **Credenciamento:** o certificado do policial é criado pelo próprio programa e autorizado pela
  lista assinada, sem editar o código nem a lista fixa de cada cópia.
- **Papéis:** usuário, revisor e administrador.
- **Ferramenta `admin_licencas.py`** (fora do instalador): emitir, renovar, transferir, revogar,
  credenciar, descredenciar, trocar administradores (para recuperar uma conta) e publicar.
  - Recusa quem não tem certificado administrativo.
  - Registra cada operação com uma linha assinada em `registro.jsonl`.

## NIST a partir do ativo (aba nova "Ativos e achados")
- **Cadastro de ativos:** computador, servidor, domínio, repositório, sistema e outros, com
  identificador, responsável, criticidade, fabricante, produto e versão.
- **Fluxo do achado:**
  1. Fonte ou coleta.
  2. Achado, com origem, identificador, data do evento e da consulta, e um instantâneo como evidência
     com SHA-256.
  3. Descarte com motivo **ou** confirmação, com: resultado oficial do CSF 2.0, prioridade justificada,
     responsável, prazo e ação. Para o KEV, a confirmação também exige o boletim do fabricante e a
     versão do ativo.
  4. Correção, com evidência obrigatória.
  5. **Revisor** encerra ou devolve. Quem corrigiu não pode revisar.
- **Linha do tempo** encadeada por hash (`achado_log`): autor, data e estado anterior → novo.
- **Incidente** aberto a partir do achado, com o mesmo cadastro e o vínculo ao processo SEI.
- **Nova coleta ou consulta da mesma ocorrência:** atualiza a última observação e preserva a decisão.
  Se a fonte divergir da decisão, o achado fica marcado com uma **divergência** para revisão.
- **Painel:** mostra ações vencidas, divergências, correções aguardando verificação e a contagem por
  responsável. Um clique duplo abre o registro.
- **Relatório PDF:** seção 7, de achados. Consolidação e auditoria passam a ser as seções 8 e 9.

## Fontes abertas
- **CISA KEV:** consulta por CVE e varredura pelo fabricante e produto do ativo. O catálogo fica em
  cache diário, com espelho no GitHub.
- **Have I Been Pwned:**
  - catálogo público (`/api/v3/breaches`);
  - busca por domínio verificado (`/breacheddomain`), só com a chave do plano e para ativo autorizado;
  - e-mails mascarados.
- **GitHub Secret Scanning:** só repositório autorizado, com `hide_secret=true`. Guarda número, tipo,
  estado e link; o segredo nunca é guardado.
- **Pwned Passwords:** na criação e na troca de senha, por k-anonimato. Só o prefixo do SHA-1 sai do
  computador, com `Add-Padding`.
- **Situações separadas na interface:**
  - correspondência;
  - sem correspondência;
  - sem configuração;
  - acesso recusado;
  - limite de consultas (com Retry-After);
  - fonte indisponível.
- **Credenciais:** cifradas com a chave do certificado. Só revisor ou administrador as configura, e
  elas nunca aparecem em relatórios, auditoria ou exportação.

## Instalador Windows
- `SCyberPM-Setup-1.6.exe`, feito com PyInstaller e Inno Setup:
  - instalação por usuário, sem pedir administrador;
  - atalhos no menu Iniciar (programa, painel NIST e diagnóstico) e na área de trabalho.
- **Workflow "Instalador Windows", no windows-latest:**
  - gera o instalador e instala em silêncio;
  - confere o atalho;
  - **abre o executável instalado pelo destino do atalho** em modo diagnóstico;
  - atualiza por cima, conferindo que o id da instalação se mantém;
  - desinstala, conferindo que os dados do usuário ficam;
  - publica o SHA-256.
- O instalador ainda não é assinado. A assinatura de código depende de um certificado de assinatura
  da PMGO.

## Qualidade
- 110 testes automáticos:
  - `test_ativacao.py`: licenças, revogação, transferência, usuário comum, recuperação de
    administrador, diagnóstico e migração de perfil;
  - `test_achados.py`: fluxo completo com reinício, divergências e fontes, com respostas no formato
    oficial de cada API;
  - a **consulta real** a CISA KEV, catálogo HIBP e Pwned Passwords roda no CI.
