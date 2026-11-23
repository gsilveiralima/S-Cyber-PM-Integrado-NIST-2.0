# S-Cyber PM 1.5 + NIST Intelligence 1.0.0 — versão para uso real

Esta versão consolida o que foi validado no Windows 11 em 22/11/2026
(`VALIDACAO_WINDOWS_2026-11-22.md`).

## Autenticação (S-Cyber PM 1.5)
- Lista `CERTIFICADOS_AUTORIZADOS`, com um certificado por usuário. Inclui o certificado do SGT Gabriel
  (`B330B18E…`) ao lado do certificado do MAJ Leonídio.
- `ACS_AUTORIZADAS` e `TITULAR_DEVE_CONTER` para os certificados da instituição, sempre com
  cadeia e revogação conferidas.
- Troca obrigatória das senhas de fábrica no primeiro acesso, com política de senha forte.
- O certificado validado no login passa a ser o usado pelas Opções e pela assinatura de documentos.

## NIST Intelligence 1.0.0
- Catálogo CSF 2.0 completo (106 subcategorias), maturidade 0–4, Tiers e plano de ação.
- Coleta técnica do Windows ligada às subcategorias, riscos com mapa de calor, incidentes com
  prazo da ANPD, cadeia de custódia encadeada por hash, OSINT, SEI e relatório PDF assinado.
- Banco cifrado (AES-256-GCM) com chave derivada do certificado.
- Correções de exibição no tema nativo do Windows (cabeçalhos das tabelas, gráfico e legenda).

## Instalação e manutenção
- `docs/INSTALACAO_WINDOWS.md`: passo a passo validado, sem Git, com a tabela de problemas encontrados.
- `requirements-lock.txt`: versões exatas validadas, para instalação reproduzível.
- `adicionar_certificado.py`: inclui um usuário na lista sem editar o código à mão.
- `verificar_certificados.ps1`: diagnóstico de todos os certificados da lista (substitui
  `verificar_certificado_original.ps1`).
- `CERTIFICADOS.md`: substitui `CERTIFICADO_ORIGINAL_VERIFICACAO.md`.
- `gerarExe.py`: declara os módulos do painel NIST e da troca de senha para o PyInstaller.
- `testar_integracao_windows.bat`: usa o ambiente `.venv`.
- `docs/README_PRIMEIRO.md` removido, por estar desatualizado.
- 42 testes automáticos.
