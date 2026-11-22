# Uso do certificado original do S-Cyber PM — cópia integrada v0.3.1

## O que foi encontrado

No ZIP `S-Cyber-prj-main(1).zip`, o arquivo `dist/S-Cyber PM.cer` possui:

- Nome do titular: `CN=S-Cyber PM`
- Thumbprint SHA-1 usado como identificador no Windows: `ECD4B39DE69C171732449C0D8378F312661482DA`
- Validade: 14/11/2026 a 14/11/2027.

O `appSCyberPM.py` do mesmo ZIP original continha outro thumbprint, `1046998520BF09EAF69CEF2AD55DA1ED739A1E6C`.
A cópia integrada v0.3.1 passa a apontar para o arquivo `.cer` fornecido no ZIP
original. **O repositório original não foi alterado.**

## Etapa 1 — Confira a chave privada NO MESMO usuário Windows

Abra o PowerShell na pasta `S-Cyber-PM-Integrado` e rode:

```powershell
.\verificar_certificado_original.ps1
```

Caso a execução de scripts esteja bloqueada, rode o diagnóstico equivalente, sem alterar a política:

```powershell
Get-Item 'Cert:\CurrentUser\My\ECD4B39DE69C171732449C0D8378F312661482DA' -ErrorAction SilentlyContinue |
    Select-Object Subject,Thumbprint,HasPrivateKey,NotBefore,NotAfter
```

Se esse comando não exibir nada, o certificado não está instalado no repositório
**Pessoal** da conta atual. `HasPrivateKey=True` é necessário, mas não garante
sozinho que o processo tem permissão para usar a chave.

**Importar apenas o `.cer` não resolve**: ele contém somente a chave pública.
É necessário que a **chave privada correspondente** já esteja na conta do Windows
ou seja disponibilizada legitimamente pelo responsável, quando exportável.

## Etapa 2 — Execute a cópia integrada

```powershell
py -3 appSCyberPM.py
```

Se usar ambiente virtual, utilize o Python da `.venv` preparado conforme
`INSTRUCOES_INTEGRACAO.md`.

## Se o certificado de thumbprint anterior estiver no Windows

Se o diagnóstico indicar que somente `1046998520BF09EAF69CEF2AD55DA1ED739A1E6C` existe com chave privada,
**não crie um novo certificado**. Há duas versões diferentes de certificado no
material original. A cópia anterior v0.3.0 estava configurada para esse identificador.
Nesse cenário, utilize a cópia v0.3.0 ou ajuste **apenas a cópia integrada** para
esse thumbprint, após confirmação de que ele corresponde ao certificado autorizado.
Não faça a troca no repositório original sem aprovação dos responsáveis.

## Observações de segurança

- O mecanismo de desafio e resposta RSA e a exigência de chave privada foram preservados.
- `EXIGIR_CADEIA_VALIDA` não foi alterado em relação ao aplicativo original.
- A chave privada não está no arquivo `.cer` e não foi incluída neste pacote.
- O arquivo de opções em `%APPDATA%\SCyberPM` é protegido por chave derivada do
  certificado. A troca de certificado pode tornar dados cifrados antigos ilegíveis;
  faça backup legítimo desses dados antes de qualquer migração autorizada.
- A autenticação em Windows, com chave privada e conta reais, não pode ser validada
  neste ambiente. A aplicação só será liberada quando a assinatura do desafio funcionar.
