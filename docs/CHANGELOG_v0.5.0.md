# S-Cyber NIST Intelligence — v0.5.0

## Criptografia em repouso do banco NIST
- Os campos de texto sensíveis são cifrados com **AES-256-GCM** (`nist_intelligence/crypto.py`):
  riscos, incidentes, linha do tempo, evidências, custódia, avaliação, OSINT e dados da coleta técnica.
- A chave **não é armazenada**. Ela deriva por HKDF-SHA256 da chave que o S-Cyber PM obtém com a
  chave privada do certificado (`formOpcoes`), e a chave das Opções nunca é reutilizada diretamente.
- Um token de verificação recusa abrir o banco com outro certificado ou sem certificado. Nada é
  apagado: a mensagem explica o motivo.
- O banco em claro da v0.4 é **migrado na primeira abertura** e passa por `VACUUM`, para não sobrar
  texto em páginas livres. `PRAGMA secure_delete=ON` sobrescreve os registros excluídos.
- As cadeias de hash (custódia e incidentes) são calculadas sobre o texto em claro e continuam
  verificáveis. Cifra adulterada é detectada.
- A interface e o relatório leem os dados pelo `core` (`risks`, `evidence_list`, `osint_list`...),
  sem SQL direto.

## Testes
- 31 testes automáticos, 7 deles novos (`tests/test_criptografia.py`): nada em claro no disco,
  leitura com a chave certa, recusa com outro certificado ou sem chave, migração da v0.4 e detecção
  de cifra adulterada.
