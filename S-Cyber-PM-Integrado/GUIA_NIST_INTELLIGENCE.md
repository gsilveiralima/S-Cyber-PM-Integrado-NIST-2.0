# Guia do S-Cyber NIST Intelligence 1.0.0

Abra pelo menu ou pela Ribbon **NIST Intelligence** (ou **Ctrl+Shift+N**), depois do login do S-Cyber PM.

**Tour narrado:** em *Arquivo > Tour* (ou `F2`), a narradora abre o painel e explica cada aba, para que
serve e como usar, na ordem do fluxo abaixo.

## Fluxo de trabalho recomendado
1. **Coleta técnica**: clique em *Executar verificação agora*. De preferência, abra o S-Cyber PM
   como Administrador. O Windows é consultado somente para leitura, e cada resultado é ligado às
   subcategorias do CSF.
2. **Avaliação CSF 2.0**: percorra as 106 subcategorias e informe a maturidade atual e a alvo (0–4),
   o responsável e o prazo. Use o filtro *Com falha técnica* para começar pelo que a coleta reprovou.
   Defina também o **Tier** (1–4) de cada função.
3. **Plano de ação**: reúne as lacunas automaticamente, com prioridade = lacuna × 2 quando há
   falha técnica. Clique duas vezes num item para editá-lo.
4. **Riscos**: registre ameaça, vulnerabilidade, P×I (1–3), tratamento e risco residual. O mapa de
   calor é atualizado sozinho.
5. **Incidentes**: marque *Envolve dados pessoais* para calcular o prazo de 3 dias úteis de
   comunicação à ANPD (Res. CD/ANPD nº 15/2024, art. 6º). Feriados não são descontados.
   Registre cada fase na linha do tempo.
6. **Evidências e custódia**: o hash SHA-256 é registrado, junto com cada transferência ou análise.
   *Reverificar arquivo* detecta alterações e *Verificar cadeia* detecta registros adulterados ou apagados.
7. **Relatório**: gera o PDF consolidado. Dentro do S-Cyber PM, ele pode ser **assinado com o
   certificado** e **protegido com a senha de PDF** das Opções (módulo original `modPDFProtegido`).

## Escalas
- Maturidade: 0 Inexistente · 1 Inicial · 2 Parcial · 3 Implementado · 4 Gerenciado.
- Tiers do CSF 2.0: 1 Parcial · 2 Informado por riscos · 3 Repetível · 4 Adaptativo.
- Risco: P×I de 1 a 9; baixo (1–2), médio (3–4), alto (6–9).

## Limites
- O banco fica em `%APPDATA%\SCyberPM\nist\nist.db`. Os textos são cifrados (AES-256-GCM) com uma chave
  derivada do certificado. Se o certificado for trocado, o banco antigo não abre com o novo: o painel
  avisa e não apaga nada. Antes de trocar o certificado, exporte os CSVs.
- No modo de teste (`teste_painel_nist.py`), o banco é temporário e não é cifrado.
- A coleta técnica avalia somente o computador em que roda.
- A cadeia de custódia apoia, mas não substitui, o procedimento pericial oficial.
- As descrições das subcategorias são traduções resumidas; a referência é o NIST CSWP 29.
