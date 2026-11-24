# Certificados digitais do S-Cyber PM

O S-Cyber PM só abre depois de um **desafio e resposta**: o Windows assina um número aleatório com
a **chave privada** de um certificado autorizado, e o aplicativo confere a assinatura. Quem não
tem essa chave privada no próprio Windows não entra.

## Certificados autorizados

A lista fica no início do `appSCyberPM.py`, em `CERTIFICADOS_AUTORIZADOS`:

| Titular | Thumbprint (SHA-1) | Validade | Usuário |
|---|---|---|---|
| `CN=S-Cyber PM` | `ECD4B39DE69C171732449C0D8378F312661482DA` | 14/11/2026 a 14/11/2027 | MAJ Leonídio |
| `CN=S-Cyber-PM-NIST-2.0` | `B330B18E7E10C2F4F9182E911516A13DA0591CC9` | 22/11/2026 a 22/11/2027 | SGT Gabriel |
| `CN=S-Cyber-PM-NIST-2.0 - SGT Gabriel - defesa.cibernetica` | `7CB36ED157A30DCEA274B44450B78C16370F15EE` | 24/11/2026 a 24/11/2027 | SGT Gabriel (conta `defesa.cibernetica`) |

O arquivo `certificados/S-Cyber PM.cer` é a parte **pública** do primeiro certificado. Ele não
tem a chave privada, e importá-lo **não** libera o acesso.

## Conferir o seu computador

```powershell
powershell -ExecutionPolicy Bypass -File .\verificar_certificados.ps1
```

O script só lê: mostra, para cada certificado da lista, se ele está instalado no usuário atual,
se tem chave privada e se está dentro da validade.

## Incluir um usuário

1. No Windows do novo usuário, crie o certificado (em produção, use o da instituição; veja abaixo):
   ```powershell
   $c = New-SelfSignedCertificate -Subject "CN=S-Cyber-PM-NIST-2.0 - NOME" `
        -KeyAlgorithm RSA -KeyLength 2048 -KeyExportPolicy NonExportable `
        -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddYears(1)
   ```
2. Inclua-o na lista e confira:
   ```powershell
   .\.venv\Scripts\python.exe adicionar_certificado.py $c.Thumbprint "CN=S-Cyber-PM-NIST-2.0 - NOME"
   powershell -ExecutionPolicy Bypass -File .\verificar_certificados.ps1
   ```
3. Envie a alteração do `appSCyberPM.py` ao repositório e gere o `.exe` de novo, se for o caso.
4. Atualize a tabela acima.

A chave é criada **não exportável**: ela não sai da conta do Windows em que foi criada. Uma
outra conta no mesmo computador (por exemplo, `defesa.cibernetica`) precisa do próprio certificado.
Mantenha **uma só cópia** da pasta do programa: o `adicionar_certificado.py` altera apenas o
`appSCyberPM.py` da pasta em que é executado. Por isso, cada
usuário tem o seu certificado, e o sistema sabe quem entrou e quem assinou cada documento.

## Produção: certificados da instituição

Em `appSCyberPM.py`:

- `ACS_AUTORIZADAS`: thumbprint da **AC própria da PMGO**. Assim, qualquer certificado emitido por
  ela é aceito, sempre com cadeia e revogação conferidas on-line.
- `TITULAR_DEVE_CONTER`: por exemplo, `O=Policia Militar do Estado de Goias`.
- Não coloque em `ACS_AUTORIZADAS` uma AC **pública** da ICP-Brasil: ela emite e-CPF para qualquer
  cidadão. Nesse caso, cadastre os certificados um a um ou preencha `TITULAR_DEVE_CONTER`.
- `EXIGIR_CADEIA_VALIDA = True` exige cadeia também para os certificados da lista, mas recusa os
  certificados de laboratório (autoassinados).

Detalhes em `../docs/PRODUCAO_SEGURANCA.md`.

## Troca ou vencimento do certificado

O arquivo de Opções (`%APPDATA%\SCyberPM\scyber_pm.opcoes`) e o banco do NIST Intelligence
(`%APPDATA%\SCyberPM\nist\nist.db`) são cifrados com uma chave derivada do certificado do usuário.
Antes de trocar o certificado:

- exporte os CSVs do painel NIST;
- anote as configurações.

Com o certificado novo, esses dados antigos não abrem.
