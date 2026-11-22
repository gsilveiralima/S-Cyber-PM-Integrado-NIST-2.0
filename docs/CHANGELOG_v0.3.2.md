# S-Cyber PM + NIST Intelligence — v0.3.2

Só o módulo NIST foi alterado. Os arquivos originais do S-Cyber PM (inclusive o
`appSCyberPM.py` da v0.3.1) continuam com o mesmo SHA-256.

## Correções
- **SEI no executável (.exe):** a ponte carregava o `formExploreSEI.py` pelo caminho do
  arquivo (`exec_module`). Isso falha no PyInstaller, onde os `.py` não existem.
  Agora o módulo é importado normalmente.
- **Execução de código por configuração:** o caminho vinha de um JSON gravado na pasta do
  usuário. Quem alterasse esse arquivo fazia o programa executar outro `.py`. A leitura do
  JSON e o `subprocess` para abrir o "original" foram removidos.
- **Cores dos títulos:** os estilos `NIST.Title/Section/Info.TLabel` não herdam de
  `NIST.TLabel` e apareciam com fundo cinza sobre o painel escuro.
- **SQL:** `actual<>"Não avaliado"` usava aspas duplas como texto, um recurso obsoleto que
  falha no SQLite compilado com `DQS=0`. Agora usa parâmetro.
- **Saída do programa:** o painel não encerrava a sessão SEI nem fechava o banco. Agora isso
  acontece no `<Destroy>`.
- **Senha SEI:** era apagada do campo antes da validação dos campos e o usuário precisava
  digitá-la de novo.
- **Origem SEI:** `host` e `host:443` passam a ser tratados como a mesma origem.

## Segurança
- CSV exportado protegido contra injeção de fórmulas (`=`, `+`, `-`, `@`), usando `;` para o Excel em pt-BR.
- Limite de 2000 caracteres e validação centralizada no `core.py` em todos os cadastros.
- O `teste_painel_nist.py`, que dispensava o login, só roda com `SCYBER_NIST_DEV=1`. Ele usa
  um banco temporário e nunca abre os dados reais.
- O banco passa para `%APPDATA%\SCyberPM\nist\`, a mesma pasta do aplicativo. O banco antigo é copiado, não movido.

## Melhorias
- Exclusão de registros (riscos, OSINT, incidentes, evidências), com confirmação.
- Matriz de riscos ordenada por P×I, com coluna e cor de nível (baixo/médio/alto).
- Exportação CSV também de incidentes e evidências.
- O SHA-256 é calculado em segundo plano, sem congelar a janela.
- Diálogos ligados ao painel (`parent`), Enter para pesquisar no SEI, versão única (0.3.2).
- Testes: de 6 para 15 (redirecionamento bloqueado, senha na URL, CSV, exclusão, validações).
