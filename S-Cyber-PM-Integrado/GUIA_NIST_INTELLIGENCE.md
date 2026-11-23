# Guia do S-Cyber NIST Intelligence 1.2.0

O NIST Intelligence funciona **dentro do S-Cyber PM**, depois do certificado e do login, com banco
cifrado e trilha de auditoria. Formas de abrir:

| Como | Onde |
|---|---|
| Direto no painel | `appSCyberPM.py --nist`, ou dois cliques em `iniciar_nist_windows.bat` (no `.exe`: `SCyberPM.exe --nist`) |
| Atalho | **Ctrl+Shift+N** |
| Menu **NIST Intelligence** | painel ou uma aba específica (Coleta técnica, Riscos, Incidentes, Relatório, Auditoria…) |
| Ribbon | aba **NIST Intelligence** |
| Assistente (campo central) | escreva, por exemplo, "coleta técnica", "incidentes", "relatório nist" ou "auditoria" |

**Tour narrado:** em *Arquivo > Tour* (ou `F2`), a narradora abre o painel e explica cada aba.

**Ao entrar no S-Cyber PM** (depois do login), sem atrasar a abertura:
- é feita uma **cópia de segurança diária** do banco NIST na pasta `backups`, guardando as últimas 7;
- aparece uma **notificação do Windows** se houver prazo da ANPD vencido ou vencendo, ações ou
  tratamentos de risco vencidos, registros adulterados ou certificado vencendo em 60 dias ou menos.
  A notificação mostra só números de registro, nunca títulos.

> `teste_painel_nist.py` **não** é o painel de uso real: abre só a interface, com banco temporário e
> sem criptografia, para desenvolvimento (exige `SCYBER_NIST_DEV=1`).

## Fluxo de trabalho recomendado
1. **Coleta técnica.** Integrado ao S-Cyber PM, o painel refaz a coleta **sozinho** quando a última
   tem mais de 7 dias. A coleta roda em segundo plano e só lê o Windows.
   - A aba mostra o que **melhorou ou piorou** desde a coleta anterior. Uma piora vira alerta no Painel.
   - *Aplicar à avaliação CSF* preenche as subcategorias **ainda não avaliadas** ligadas à coleta,
     com OK = 3, Atenção = 2 e Falha = 1, e alvo 3.
   - O que alguém já avaliou **não é alterado**: as divergências aparecem para revisão.
   - Para obter BitLocker, Secure Boot e backup, abra o S-Cyber PM como Administrador.
   - **Outros computadores** (sem o S-Cyber PM):
     1. clique em *Salvar coletor avulso (.ps1)…* e escolha um pendrive;
     2. no outro computador, clique com o botão direito em `coletar_nist_windows.bat` e escolha
        *Executar como administrador*;
     3. traga o `coleta_<COMPUTADOR>_<data>.json` e use *Importar coleta de outro computador…*.

     A lista de computadores mostra a última coleta de cada um; clique num deles para ver o
     resultado. A avaliação usa a **pior situação** entre os computadores.
2. **Avaliação CSF 2.0.** Revise as 106 subcategorias: maturidade atual e alvo (0–4), responsável e
   prazo. O filtro *Com falha técnica* mostra primeiro o que a coleta reprovou. Defina também o
   **Tier** (1–4) de cada função.
   - **Evidências desta subcategoria:** *Anexar arquivo novo…* registra o arquivo (política,
     print, relatório) na cadeia de custódia com SHA-256 e o liga à subcategoria. *Anexar já
     registrada…* usa uma evidência existente. A coluna *Evid.* mostra quantas cada uma tem.
3. **Plano de ação.** Reúne as lacunas automaticamente, com prioridade = lacuna × 2 quando há falha
   técnica. Clique duas vezes num item para editá-lo.
4. **Riscos.** Registre ameaça, vulnerabilidade, P×I (1–3), tratamento e risco residual. O mapa de
   calor é atualizado sozinho.
5. **Incidentes.**
   - Marque *Envolve dados pessoais* para calcular o prazo de 3 dias úteis de comunicação à ANPD
     (Res. CD/ANPD nº 15/2024, art. 6º). O prazo desconta fins de semana e os feriados
     nacionais (calculados sozinhos, inclusive a Paixão de Cristo e o 20 de novembro).
   - **Feriados…:** cadastre os feriados estaduais e municipais da unidade, e também Carnaval e
     Corpus Christi se não houver expediente (são ponto facultativo). O prazo dos incidentes ainda
     não comunicados é recalculado, e a mudança entra na linha do tempo.
   - Registre cada fase na linha do tempo.
   - **Processo SEI:** vincule o incidente ao processo administrativo. Na aba Incidentes, use
     *Processo SEI…*. Na aba **Consultas SEI**, selecione o incidente, ache o processo e clique em
     *Vincular ao incidente selecionado*. O vínculo entra na linha do tempo e no relatório.
6. **Evidências e custódia.** O SHA-256 é registrado, junto com cada transferência ou análise.
   - *Reverificar arquivo* detecta alterações no arquivo.
   - *Verificar cadeia* detecta registros da custódia adulterados ou apagados.
7. **Consolidação** (várias unidades).
   - Na unidade que envia, informe o nome da unidade e uma senha (12 ou mais caracteres, 3 tipos) e
     clique em *Gerar pacote assinado…*. O pacote `.scnist` é assinado com o seu certificado e
     cifrado com a senha. Mande a senha **por outro canal**.
   - Na unidade consolidadora, use *Importar pacote…*. A assinatura é conferida, e o certificado é
     comparado com a lista de autorizados. Se o certificado não estiver na lista, o pacote só entra
     com confirmação e fica marcado como **NÃO** autorizado.
   - A tabela mostra cada unidade e a média: maturidade por função, riscos altos, incidentes abertos
     e prazos da ANPD vencidos.
   - O pacote leva só dados minimizados: não há títulos de riscos ou incidentes, notas nem nomes.
8. **Relatório.** Gera o PDF consolidado, com a trilha de auditoria. Dentro do S-Cyber PM, ele é
   **assinado com o certificado** e pode ser **protegido com a senha de PDF** das Opções.
9. **Backup e retenção** (aba Relatório).
   - *Fazer backup* gera uma cópia que continua cifrada com o certificado.
   - *Restaurar backup* confere o certificado e as cadeias de hash antes de trocar o banco, e guarda
     o banco atual ao lado.
   - *Abrir pasta das cópias automáticas* mostra as cópias diárias.
   - **Retenção de dados (LGPD):** informe o prazo de guarda (padrão sugerido: 1825 dias, ou
     5 anos; mínimo de 30) e clique em *Aplicar retenção…*.
     - São excluídos os incidentes **encerrados** há mais tempo que o prazo, com a linha do tempo deles.
     - Antes, um backup completo é salvo onde você escolher.
     - A operação é recusada se a linha do tempo estiver adulterada e fica registrada na auditoria.
10. **Auditoria.** Registra cada alteração, exportação, relatório e backup, com o usuário do
   S-Cyber PM, a conta do Windows e o certificado. A trilha é encadeada por hash: *Verificar
   integridade* detecta qualquer registro alterado ou apagado.

## Escalas
- Maturidade: 0 Inexistente · 1 Inicial · 2 Parcial · 3 Implementado · 4 Gerenciado.
- Tiers do CSF 2.0: 1 Parcial · 2 Informado por riscos · 3 Repetível · 4 Adaptativo.
- Risco: P×I de 1 a 9; baixo (1–2), médio (3–4), alto (6–9).

## Dados e limites
- O banco fica em `%APPDATA%\SCyberPM\nist\nist.db`.
  - Os textos, inclusive quem fez cada ação, são cifrados (AES-256-GCM) com uma chave derivada do certificado.
  - Se o certificado for trocado, o banco antigo não abre com o novo: o painel avisa e não apaga nada.
  - Antes de trocar o certificado, faça um backup e exporte os CSVs.
- A coleta técnica avalia o computador em que roda e os computadores cujas coletas foram importadas.
- O pacote de consolidação só pode ser gerado dentro do S-Cyber PM, porque usa o certificado validado no login.
- A cadeia de custódia apoia, mas não substitui, o procedimento pericial oficial.
- As descrições das subcategorias são traduções resumidas; a referência é o NIST CSWP 29.
