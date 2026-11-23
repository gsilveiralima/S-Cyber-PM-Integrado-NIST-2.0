# S-Cyber NIST Intelligence 1.2.0 — várias unidades, feriados e retenção

Esta versão estende o NIST Intelligence para além do computador em que o S-Cyber PM está instalado.
Ela também fecha três lacunas de uso real: os feriados no prazo da ANPD, as cópias de segurança e a
retenção de dados.

## Prazo da ANPD com feriados
- O prazo de 3 dias úteis (Res. CD/ANPD nº 15/2024, art. 6º) desconta:
  - sábados e domingos;
  - os **feriados nacionais**: Leis 662/1949, 6.802/1980, 9.093/1995 (Paixão de Cristo, calculada pela
    Páscoa) e 14.759/2023 (20 de novembro).
- **Feriados estaduais e municipais** são cadastrados em *Incidentes → Feriados…*:
  - Carnaval e Corpus Christi são ponto facultativo e só contam se forem cadastrados;
  - cadastrar ou remover um feriado recalcula o prazo dos incidentes ainda não comunicados;
  - cada mudança de prazo entra na linha do tempo encadeada.

## Vários computadores
- **Coletor avulso** (`coletor_nist.ps1` e `coletar_nist_windows.bat`):
  - faz as mesmas consultas somente de leitura da coleta técnica, num computador **sem** o S-Cyber PM;
  - grava um `.json`, que é importado em *Coleta técnica → Importar coleta de outro computador*;
  - o botão *Salvar coletor avulso* grava os dois arquivos num pendrive.
- A aba *Coleta técnica* lista a última coleta de cada computador. Ao clicar num computador, o
  resultado dele aparece embaixo.
- A avaliação, o plano de ação e *Aplicar à avaliação* usam a **pior situação** entre os computadores.
  A comparação "melhorou/piorou" é feita por computador.
- A coleta automática semanal considera só as coletas feitas neste computador.

## Consolidação entre unidades (aba nova)
- O pacote `.scnist` é **assinado pelo Windows** com o certificado de quem gera (CMS/PKCS #7, SHA-256).
  Funciona com chave não exportável.
- Ele é **cifrado com uma senha** combinada (scrypt + AES-256-GCM). A assinatura também vai cifrada:
  sem a senha, não se vê nem quem assinou.
- Os dados são **minimizados** (LGPD, art. 6º, III):
  - maturidade por função;
  - riscos sem texto e incidentes sem título nem notas;
  - prazos da ANPD e o resumo das coletas.
- Na importação:
  - a assinatura é conferida em Python (`nist_intelligence/signing.py`);
  - o certificado é comparado com a lista de autorizados do S-Cyber PM. Um certificado fora da lista
    só entra se o usuário confirmar, e fica marcado e registrado na auditoria;
  - pacote repetido ou gerado no próprio computador é recusado.
- A tabela consolidada mostra, por unidade e com uma linha de média:
  - a maturidade por função;
  - os riscos altos;
  - os incidentes abertos;
  - os prazos da ANPD vencidos.

## Evidências por subcategoria
- Na *Avaliação CSF 2.0*, cada subcategoria pode receber arquivos como prova:
  - um arquivo novo, que entra na cadeia de custódia com SHA-256;
  - ou uma evidência já registrada.
- A coluna *Evid.* mostra quantos arquivos cada subcategoria tem.
- O relatório traz a tabela de evidências por subcategoria.

## Ao entrar no S-Cyber PM
- **Cópia de segurança automática** do banco NIST: uma por dia, na pasta `backups` ao lado do banco.
  As últimas 7 são guardadas, e os textos continuam cifrados com o certificado.
- **Notificação do Windows** com os avisos:
  - prazo da ANPD vencido ou vencendo hoje ou amanhã;
  - ações do plano e tratamentos de risco vencidos;
  - integridade dos registros;
  - certificado do S-Cyber PM vencendo em 60 dias ou menos.

  A notificação não mostra títulos nem nomes. Tudo roda em segundo plano, sem atrasar a abertura.

## Retenção de dados (LGPD)
- Em *Relatório → Retenção de dados*, é possível excluir os incidentes **encerrados** há mais tempo
  que o prazo de guarda da unidade. O mínimo é 30 dias, e o padrão sugerido é 1825 (5 anos).
- Antes de excluir, um backup completo é salvo onde o usuário escolher.
- A operação só roda se a linha do tempo estiver íntegra, para nunca encobrir uma adulteração.
- Depois de excluir:
  - a cadeia é recalculada, e a auditoria registra o hash anterior e o novo;
  - as evidências ficam, sem o vínculo com o incidente.

## Relatório PDF
- Seção 6: tabela por computador e o resultado de cada um.
- Seção 7 (quando há pacotes): consolidação entre unidades. A trilha de auditoria passa a ser a seção 8.
- Textos com `<`, `>` ou `&` não quebram mais a geração do PDF.

## Correções
- `NISTPanel.close()` não existia: a janela de teste falhava ao fechar, e o fechamento chamava
  `destroy()` dentro do próprio evento de destruição.

## Qualidade
- 76 testes automáticos:
  - 19 em `tests/test_nist_v12.py`;
  - 4 em `tests/test_windows_v12.py`, que rodam **de verdade no Windows do CI**:
    - criam um certificado temporário de chave não exportável;
    - assinam pelo .NET e conferem a assinatura em Python;
    - geram e importam um pacote;
    - executam o coletor avulso e importam o resultado.
- Um teste mantém o `coletor_nist.ps1` versionado idêntico ao gerado pelo aplicativo.
