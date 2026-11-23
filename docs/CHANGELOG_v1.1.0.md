# S-Cyber NIST Intelligence 1.1.0 — integração de uso real

Esta versão faz o NIST Intelligence funcionar como parte do trabalho diário no S-Cyber PM, e não
como um painel isolado.

## Integração com o S-Cyber PM
- `appSCyberPM.py --nist` (e `iniciar_nist_windows.bat`, ou `SCyberPM.exe --nist`) abre o
  aplicativo direto no painel, **depois** do certificado e do login.
- Menu **NIST Intelligence** com atalho para cada aba.
- Assistente: novos comandos para coleta técnica, avaliação, riscos, incidentes, relatório e auditoria.
- `teste_painel_nist.py` explica que é só para desenvolvimento e mostra como abrir o painel real.

## Funções novas
- **Trilha de auditoria** (aba *Auditoria* e seção 7 do relatório):
  - registra cada alteração, exportação, relatório e backup, com o usuário do S-Cyber PM, a conta do
    Windows e o certificado;
  - é encadeada por hash, com alerta no Painel se for adulterada;
  - grava quem fez e o resumo cifrados no disco.
- **Coleta contínua:**
  - o painel integrado refaz a coleta sozinho quando a última tem 7 dias ou mais;
  - compara com a coleta anterior e mostra o que melhorou ou piorou; uma piora vira alerta.
- **Aplicar coleta à avaliação:**
  - preenche as subcategorias ainda não avaliadas com a maturidade sugerida;
  - nunca altera o que alguém já avaliou, e lista as divergências para revisão.
- **Incidente ligado ao SEI:**
  - campo *Processo SEI*, preenchido à mão ou a partir do resultado da consulta;
  - o vínculo entra na linha do tempo e no relatório;
  - *Abrir no navegador* abre o processo encontrado.
- **Backup e restauração** do banco cifrado:
  - a restauração confere o certificado e as cadeias de hash numa cópia antes de trocar o banco;
  - o banco atual é guardado ao lado.

## Qualidade
- 53 testes automáticos: 7 novos em `tests/test_nist_v11.py`, mais os ajustes nos existentes.
- A referência da auditoria (em claro) guarda só identificadores; endereços, nomes de computador e
  textos ficam no resumo cifrado. Os testes de criptografia acharam esse vazamento durante o
  desenvolvimento, e ele foi corrigido antes da publicação.
