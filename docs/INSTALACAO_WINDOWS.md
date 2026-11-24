# Instalação no Windows 11 — passo a passo validado

> **Usuário final:** use o instalador e o [guia curto](GUIA_WINDOWS_INSTALADOR.md). Este documento é para quem roda o código-fonte (desenvolvimento e suporte).

Roteiro seguido e aprovado em **22/11/2026** num Windows 11 x64 com Python 3.14.8.
Cada passo traz o resultado que deve aparecer. Os comandos são para o **PowerShell**.
Não é preciso instalar o Git.

> Tempo estimado: 15 a 20 minutos, a maior parte no download das dependências.

## 1. Python

Instale o Python 3.11 ou superior, de [python.org](https://www.python.org/downloads/) ou com
`winget install Python.Python.3.14`, e marque **"Add python.exe to PATH"**. Depois confira:

```powershell
py -3 --version
```

✅ `Python 3.14.8` (ou qualquer versão 3.11 ou superior).

## 2. Baixar o S-Cyber PM

Abra o PowerShell **normal** (não como Administrador):

```powershell
cd $HOME\Downloads
Invoke-WebRequest https://github.com/gsilveiralima/S-Cyber-PM-Integrado-NIST-2.0/archive/refs/heads/main.zip -OutFile scyber-pm.zip
Expand-Archive scyber-pm.zip -DestinationPath scyber-pm -Force
cd .\scyber-pm\S-Cyber-PM-Integrado-NIST-2.0-main\S-Cyber-PM-Integrado
Test-Path .\formTrocaSenha.py
```

✅ `True`: você está na pasta certa. **Todos os comandos seguintes rodam nesta pasta.**

## 3. Ambiente e dependências

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
```

✅ O último comando termina com `Successfully installed ...`.
O `requirements-lock.txt` traz as versões exatas que foram validadas. Se alguma não estiver
disponível no seu computador, use `requirements.txt` (versões mínimas).

## 4. Testes automáticos

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

✅ `Ran 110 tests ... OK` (no Windows os 4 testes de `test_windows_v12.py` rodam de verdade e
criam e apagam um certificado temporário de teste). Também dá para dar dois cliques em `testar_integracao_windows.bat`.

## 5. Certificado digital do usuário

O S-Cyber PM só abre com um certificado **autorizado**, com a **chave privada** no Windows do
próprio usuário. O arquivo `.cer` do projeto **não serve** para isso, porque não tem a chave
privada. O certificado de outra pessoa também não pode ser copiado: ele é criado como
não exportável. Por isso, cada usuário usa o seu.

**Se você já é um dos usuários cadastrados**, confira:

```powershell
powershell -ExecutionPolicy Bypass -File .\verificar_certificados.ps1
```

✅ `RESULTADO: este usuario tem um certificado autorizado e pronto`. Nesse caso, siga para o passo 6.

**Se você é um usuário novo** (certificado de laboratório; em produção, use o certificado da
instituição; veja `S-Cyber-PM-Integrado/CERTIFICADOS.md`):

```powershell
$c = New-SelfSignedCertificate -Subject "CN=S-Cyber-PM-NIST-2.0 - SEU NOME" `
     -KeyAlgorithm RSA -KeyLength 2048 -KeyExportPolicy NonExportable `
     -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddYears(1)
$c.Thumbprint
```

Acrescente o thumbprint à lista `CERTIFICADOS_AUTORIZADOS` do `appSCyberPM.py`. O script abaixo
faz isso sem abrir o arquivo; troque `SEU NOME`:

```powershell
.\.venv\Scripts\python.exe adicionar_certificado.py $c.Thumbprint "CN=S-Cyber-PM-NIST-2.0 - SEU NOME"
powershell -ExecutionPolicy Bypass -File .\verificar_certificados.ps1
```

✅ O seu certificado aparece como `PRONTO PARA USO`.

> ⚠ **Cole no PowerShell apenas comandos.** Uma linha de código Python (como `"ABC...",  # comentário`)
> colada no PowerShell dá `Expressão ausente após ','`. Essa linha vai dentro do arquivo, e o
> `adicionar_certificado.py` já faz isso.

Para que o certificado valha para todos que baixam o projeto, envie a alteração do
`appSCyberPM.py` ao repositório.

## 6. Primeiro acesso

```powershell
.\.venv\Scripts\python.exe appSCyberPM.py
```

Ou dê dois cliques em `iniciar_integrado_windows.bat`.

1. A abertura mostra **Certificate Validated**.
2. Num perfil novo, não há senha de fábrica nem login: abre direto a janela **Primeiro acesso:
   defina suas senhas** (o usuário é `agente`).
3. Na janela **Primeiro acesso: defina suas senhas**:
   - a senha precisa ter pelo menos 12 caracteres e misturar 3 tipos (minúsculas, maiúsculas, números, símbolos);
   - a senha de **acesso** e a dos **PDFs** precisam ser diferentes. Guarde a dos PDFs: ela abre os relatórios gerados.
4. A janela principal abre. Nas próximas vezes, entre com a sua senha.

## 7. Painel NIST Intelligence

Para entrar direto no painel, depois do certificado e do login:

```powershell
.\.venv\Scripts\python.exe appSCyberPM.py --nist
```

Também dá para dar dois cliques em `iniciar_nist_windows.bat`. Com o aplicativo já aberto: **Ctrl+Shift+N**,
menu **NIST Intelligence** ou o assistente ("coleta técnica", "incidentes"...).
✅ O cabeçalho mostra o seu usuário, o certificado, **banco cifrado** e **integrado ao S-Cyber PM**.

- **Coleta técnica:** na primeira abertura, e depois a cada 7 dias, o painel faz a coleta sozinho.
  Em seguida, use *Aplicar à avaliação CSF*. Para obter também BitLocker, Secure Boot e backup,
  abra o PowerShell **como Administrador**, entre na pasta e rode o comando acima.
- **Relatório** → marque *Assinar* e *Proteger com senha* → *Gerar relatório PDF*. Ao abrir o
  arquivo, o leitor de PDF pede a senha dos PDFs e mostra que ele está assinado.
- **Backup** (aba Relatório): a cópia automática é diária (últimas 7). Mesmo assim, faça de vez
  em quando um backup manual para fora do computador.
- **Feriados** (aba Incidentes → *Feriados…*): cadastre os feriados de Goiás e do município, para o
  prazo da ANPD ficar certo.
- **Outros computadores:** na aba Coleta técnica, use *Salvar coletor avulso (.ps1)…* num pendrive.
  No outro computador, clique com o botão direito em `coletar_nist_windows.bat` e escolha *Executar
  como administrador*. Depois importe o `.json` gerado.
- **Consolidação:** cada unidade gera o pacote assinado (aba Consolidação), e a consolidadora importa.
  Combine a senha por outro canal.

O uso de cada aba está em `S-Cyber-PM-Integrado/GUIA_NIST_INTELLIGENCE.md`.

## 8. Executável (opcional)

```powershell
.\.venv\Scripts\python.exe -m pip install pyinstaller
.\.venv\Scripts\python.exe gerarExe.py
.\dist\SCyberPM.exe
```

O `.exe` usa a lista de certificados do `appSCyberPM.py` do momento em que foi gerado.

## Problemas encontrados nos testes e soluções

| Sintoma | Causa | Solução |
|---|---|---|
| `git : O termo 'git' não é reconhecido` | Git não instalado | Não é necessário: use o download do passo 2 |
| `Required digital certificate could not be validated` / "não está instalado neste usuário" | Nenhum certificado da lista tem chave privada neste Windows | Passo 5 |
| `Expressão ausente após ','` no PowerShell | Linha de código Python colada no PowerShell | Use o `adicionar_certificado.py` do passo 5 |
| "O arquivo de opções foi alterado ou foi criado com outro certificado" | Sobrou um arquivo de Opções de outro certificado | Apague `%APPDATA%\SCyberPM\scyber_pm.opcoes` (as configurações voltam ao padrão) |
| "O banco do NIST Intelligence foi cifrado com OUTRO certificado" | O certificado do usuário foi trocado | Use o certificado antigo, ou renomeie `%APPDATA%\SCyberPM\nist\nist.db` para começar um banco novo |
| BitLocker, Secure Boot e backup aparecem como "Indisponível" na coleta | Precisam de Administrador | Rode o aplicativo pelo PowerShell como Administrador |
| PDF sem senha e sem assinatura | Gerado pela impressora "Microsoft Print to PDF" | Use os botões de exportar ou gerar do aplicativo, que aplicam a proteção |
| Consulta ao banco retorna `[]` | Ainda não há registros | Normal: cadastre um risco antes de conferir |
| `coletor_nist.ps1 não pode ser carregado porque a execução de scripts foi desabilitada` | Política de execução do PowerShell | Use o `coletar_nist_windows.bat`, que roda com `-ExecutionPolicy Bypass` só para esse script |
| "O pacote foi assinado por … que não está na lista de certificados autorizados" | O certificado de quem gerou não está em `CERTIFICADOS_AUTORIZADOS` | Inclua-o com `adicionar_certificado.py`, ou importe com confirmação (fica marcado) |
| "Senha incorreta ou pacote alterado" | Senha errada, ou arquivo corrompido ou adulterado | Confirme a senha com a unidade de origem e peça o pacote de novo |
| A notificação do Windows não aparece | Notificações desativadas, ou modo Não perturbe | Os mesmos avisos aparecem no Painel e na barra de status |

## Painel NIST sem login (só para desenvolvimento)

```powershell
$env:SCYBER_NIST_DEV=1; .\.venv\Scripts\python.exe teste_painel_nist.py
```

Abre só o painel, com um banco **temporário e sem criptografia**, apagado ao fechar. Não use para
dados reais.
