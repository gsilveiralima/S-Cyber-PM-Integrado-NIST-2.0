# Validação no Windows 11 — 22/11/2026

- **Ambiente:** Windows 11 x64 (ATLAS-DESKTOP), Python 3.14.8, dependências do `requirements-lock.txt`.
- **Responsável pelos testes:** SGT Gabriel Silveira Lima. As evidências são prints e vídeos da sessão de testes.
- **Versão testada:** pull request #3 (`seguranca-producao`), que depois foi mesclado no `main`.

| # | Item testado | Resultado | Evidência |
|---|---|---|---|
| 1 | Testes automáticos | ✅ Aprovado | 39 testes OK. A v1.0.0 acrescenta 3, num total de 42 |
| 2 | Certificado na lista de autorizados | ✅ Aprovado | `CN=S-Cyber-PM-NIST-2.0`, thumbprint `B330B18E…`; abertura com *Certificate Validated* |
| 3 | Troca obrigatória da senha de fábrica | ✅ Aprovado | A janela *Definir senhas* abriu no primeiro acesso e a senha fraca foi recusada |
| 4 | Assinatura de documentos com o certificado do login | ✅ Aprovado | *Assinatura de documentos* mostra `CN=S-Cyber-PM-NIST-2.0` |
| 5 | Painel NIST integrado, banco cifrado | ✅ Aprovado | O cabeçalho mostra *banco cifrado • integrado ao S-Cyber PM* |
| 6 | Coleta técnica real (PowerShell) | ✅ Aprovado | 16 verificações: 8 OK, 4 Atenção, 1 Falha, 3 Indisponíveis sem Administrador |
| 7 | Relatório PDF assinado e com senha | ✅ Aprovado | Assinatura PKCS#7 verificada (*Verification successful*); o Edge pediu a senha e indicou "assinado digitalmente" |
| 8 | Cabeçalhos das tabelas, gráfico e legenda | ✅ Corrigido | Commits `3179ff8` e `6ef51b6`, confirmados em vídeo |
| 9 | Texto cifrado no disco (`enc1:`) | ⏳ Opcional | Coberto pelos testes automáticos de `test_criptografia.py` |

## Achados da coleta técnica no computador de teste

| Situação | Item | Providência |
|---|---|---|
| Falha | Conta Convidado ativa e sem senha | **Corrigido:** `Disable-LocalUser`; agora `Enabled = False` |
| Atenção | Comprimento mínimo de senha 0 | Definir uma política local ou de domínio |
| Atenção | Sem bloqueio de tela automático | Configurar o bloqueio por inatividade |
| Atenção | Log de blocos de script do PowerShell desligado | Ativar por GPO |
| Atenção | Portas 135, 139 e 445 abertas | Padrão do Windows; avaliar se o compartilhamento é necessário |

## Observações

- O aviso do Edge "Não foi possível verificar algumas assinaturas" é esperado em certificado de
  laboratório (autoassinado). Com certificado institucional ou ICP-Brasil, ele não aparece.
- Um PDF gerado pela impressora "Microsoft Print to PDF" saiu sem assinatura e sem senha. Esse é
  um comportamento da versão original; oriente os usuários a usar os botões do aplicativo.
