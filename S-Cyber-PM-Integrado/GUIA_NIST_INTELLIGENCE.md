# Guia do S-Cyber NIST Intelligence 1.1.0

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
2. **Avaliação CSF 2.0.** Revise as 106 subcategorias: maturidade atual e alvo (0–4), responsável e
   prazo. O filtro *Com falha técnica* mostra primeiro o que a coleta reprovou. Defina também o
   **Tier** (1–4) de cada função.
3. **Plano de ação.** Reúne as lacunas automaticamente, com prioridade = lacuna × 2 quando há falha
   técnica. Clique duas vezes num item para editá-lo.
4. **Riscos.** Registre ameaça, vulnerabilidade, P×I (1–3), tratamento e risco residual. O mapa de
   calor é atualizado sozinho.
5. **Incidentes.**
   - Marque *Envolve dados pessoais* para calcular o prazo de 3 dias úteis de comunicação à ANPD
     (Res. CD/ANPD nº 15/2024, art. 6º). Feriados não são descontados.
   - Registre cada fase na linha do tempo.
   - **Processo SEI:** vincule o incidente ao processo administrativo. Na aba Incidentes, use
     *Processo SEI…*. Na aba **Consultas SEI**, selecione o incidente, ache o processo e clique em
     *Vincular ao incidente selecionado*. O vínculo entra na linha do tempo e no relatório.
6. **Evidências e custódia.** O SHA-256 é registrado, junto com cada transferência ou análise.
   - *Reverificar arquivo* detecta alterações no arquivo.
   - *Verificar cadeia* detecta registros da custódia adulterados ou apagados.
7. **Relatório.** Gera o PDF consolidado, com a trilha de auditoria. Dentro do S-Cyber PM, ele é
   **assinado com o certificado** e pode ser **protegido com a senha de PDF** das Opções.
8. **Backup** (aba Relatório).
   - *Fazer backup* gera uma cópia que continua cifrada com o certificado.
   - *Restaurar backup* confere o certificado e as cadeias de hash antes de trocar o banco, e guarda
     o banco atual ao lado.
9. **Auditoria.** Registra cada alteração, exportação, relatório e backup, com o usuário do
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
- A coleta técnica avalia somente o computador em que roda.
- A cadeia de custódia apoia, mas não substitui, o procedimento pericial oficial.
- As descrições das subcategorias são traduções resumidas; a referência é o NIST CSWP 29.
