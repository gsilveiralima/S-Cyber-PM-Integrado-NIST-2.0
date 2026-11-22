# S-Cyber NIST Intelligence — v0.4.0

Os arquivos originais do S-Cyber PM continuam inalterados (mesmo SHA-256 da v0.3.1).

## Novo
- **Catálogo completo do NIST CSF 2.0**: 6 funções, 22 categorias e 106 subcategorias, com os
  identificadores oficiais (`nist_intelligence/catalog.py`).
- **Avaliação por subcategoria**: maturidade 0–4, atual e alvo, com responsável, prazo, evidência e
  ação. Tiers 1–4 por função. Filtros: lacunas, não avaliadas e com falha técnica.
- **Painel**: maturidade por função, gráfico atual × alvo e alertas (prazo da ANPD, prazos vencidos,
  falhas técnicas, adulteração das cadeias).
- **Plano de ação** gerado das lacunas e priorizado pela coleta técnica. Exporta CSV.
- **Coleta técnica automática** (`collector.py`): 17 verificações somente leitura do Windows, ligadas
  às subcategorias. Inclui Defender, firewall, BitLocker, UAC, RDP/NLA, SMBv1, Secure Boot,
  atualizações, administradores, contas, política de senha, bloqueio de tela, logs, SmartScreen,
  restauração, portas expostas e validade do certificado do S-Cyber PM. Os dados brutos são gravados com SHA-256.
- **Riscos**: ameaça, vulnerabilidade, subcategoria, tratamento, responsável, prazo, risco residual,
  edição e mapa de calor 3×3.
- **Incidentes**: severidade, fases (Detecção → Lições aprendidas), prazo ANPD de 3 dias úteis e
  linha do tempo encadeada por hash.
- **Cadeia de custódia**: movimentações encadeadas por hash, reverificação do arquivo e detecção de
  registros alterados ou apagados.
- **Relatório PDF** (`report.py`): resumo, gráfico, plano, mapa de calor, incidentes, custódia e coleta.
  Pode ser assinado e cifrado com o `modPDFProtegido` original.

## Compatibilidade
- O banco da v0.3 é migrado automaticamente (novas colunas; o status dos incidentes vira fase).
- Testes: 24 testes automáticos (`tests/`).
