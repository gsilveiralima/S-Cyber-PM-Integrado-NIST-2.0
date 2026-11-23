# Preparação para produção — autenticação e senhas

Mudanças nos arquivos originais do S-Cyber PM para uso em sistemas reais da PMGO.

## 1. Troca obrigatória das senhas de fábrica

A senha de fábrica está em `formOpcoes.py`, que é público. Agora:

- no primeiro acesso (ou enquanto a senha de acesso ou a dos PDFs forem as de fábrica), o login abre
  **Definir senhas** (`formTrocaSenha.py`). O aplicativo só é liberado depois que o usuário define
  senhas próprias. Se ele sair dessa janela, o aplicativo é encerrado;
- vale também para quem entra pelo Windows Hello e para arquivos de opções de versões anteriores;
- **política de senha** (`formOpcoes.problema_senha`), aplicada também em Arquivo > Opções:
  - pelo menos 12 caracteres e 3 de 4 tipos (minúsculas, maiúsculas, números, símbolos);
  - diferente da senha de fábrica;
  - sem o nome do usuário e com pelo menos 6 caracteres distintos;
  - a senha de acesso e a dos PDFs precisam ser diferentes.

## 2. Vários certificados e AC institucional

Configuração no início de `appSCyberPM.py`:

| Variável | Uso |
|---|---|
| `CERTIFICADOS_AUTORIZADOS` | Lista de impressões digitais (SHA-1) aceitas. Cada usuário pode ter o seu. Vale o primeiro da lista encontrado no repositório Pessoal, com chave privada e dentro da validade. |
| `ACS_AUTORIZADAS` | Impressões digitais de ACs (raiz ou intermediária). Aceita qualquer certificado emitido por elas, **sempre** com cadeia válida e revogação conferida on-line. |
| `TITULAR_DEVE_CONTER` | Texto obrigatório no titular dos certificados aceitos por AC, por exemplo `O=Policia Militar do Estado de Goias`. |
| `EXIGIR_CADEIA_VALIDA` | Exige cadeia e revogação também para a lista fixa. Deixe `False` só para certificados autoassinados de laboratório. |

> **Atenção:** em `ACS_AUTORIZADAS`, coloque somente a AC **própria** da instituição. Uma AC pública da
> ICP-Brasil emite certificados para qualquer cidadão. Para e-CPF/e-PM da ICP-Brasil, cadastre os
> certificados um a um em `CERTIFICADOS_AUTORIZADOS` ou preencha `TITULAR_DEVE_CONTER`.

### Cadastrar o certificado de um usuário

No computador do usuário, no PowerShell:

```powershell
Get-ChildItem Cert:\CurrentUser\My | Where-Object HasPrivateKey |
    Select-Object Subject, Thumbprint, NotAfter | Format-List
```

Inclua o `Thumbprint` em `CERTIFICADOS_AUTORIZADOS` e gere o executável de novo. Para um certificado de
laboratório (sem PKI), o comando de criação está no cabeçalho de `appSCyberPM.py`.

### Efeitos de cada usuário ter o seu certificado

- O arquivo de Opções (`%APPDATA%\SCyberPM`) e o banco do NIST Intelligence são cifrados com uma chave
  derivada do certificado em uso. Se o certificado de um usuário for trocado, os dados antigos dele
  não abrem com o novo: antes da troca, exporte os CSVs do NIST e anote as configurações.
- Para assinar documentos, o padrão passa a ser o certificado validado no login.

## Testes
`tests/test_seguranca.py` (8 testes): política de senha, troca obrigatória (inclusive arquivo antigo e
troca pelas Opções), lista de certificados, aceite por AC com cadeia e titular, assinatura do desafio
e proteção contra injeção no script do PowerShell. Total do projeto: 76 testes.

## Consolidação, retenção e cópias (v1.2)
- Os pacotes de consolidação são aceitos sem confirmação somente quando o certificado de quem
  assinou está em `CERTIFICADOS_AUTORIZADOS`. Mantenha essa lista atualizada.
- A senha do pacote é combinada **por outro canal**, nunca no mesmo e-mail do arquivo.
- Defina por escrito o prazo de guarda dos incidentes (política de retenção da unidade) e use-o em
  *Relatório → Retenção de dados*. Guarde o backup gerado antes da exclusão conforme essa política.
- As cópias automáticas (`%APPDATA%\SCyberPM\nist\backups`) continuam cifradas com o certificado.
  Para recuperar um desastre no computador, guarde também uma cópia fora dele.

## Validação no Windows
Validado em 22/11/2026 (`VALIDACAO_WINDOWS_2026-11-22.md`): certificado da lista, troca obrigatória
de senha com recusa de senha fraca e assinatura com o certificado do login. Ainda falta validar,
quando houver, o aceite por AC institucional e a revogação on-line na rede da PMGO.
