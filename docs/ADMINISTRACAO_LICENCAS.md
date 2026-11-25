# Administração de licenças e credenciamentos — SGT Gabriel e MAJ Leonídio

Só vocês dois emitem, renovam, transferem e revogam licenças, e credenciam os certificados dos
policiais. Cada um usa a **própria conta do Windows** e o **próprio certificado administrativo**,
cuja chave privada não pode ser exportada. A autorização é conferida duas vezes:

- a ferramenta `admin_licencas.py` recusa quem não tem um certificado administrativo;
- o aplicativo instalado recusa qualquer documento que não tenha sido assinado por um administrador.

Os administradores fixados no aplicativo são:

| Administrador | Certificado (impressão digital) |
|---|---|
| MAJ Leonídio | `ECD4B39DE69C171732449C0D8378F312661482DA` |
| SGT Gabriel | `B330B18E7E10C2F4F9182E911516A13DA0591CC9` |
| SGT Gabriel (conta `defesa.cibernetica`) | `7CB36ED157A30DCEA274B44450B78C16370F15EE` |

A ferramenta **não vai no instalador**. Ela roda a partir do repositório clonado, no computador do
administrador.

## Jeito mais fácil: a tela do administrador (sem PowerShell)

Na pasta `S-Cyber-PM-Integrado`, dê **dois cliques em `Administrar licencas.bat`**. Se quiser, crie
um atalho dele na Área de Trabalho. A tela encontra sozinha o seu certificado de administrador.

**Ativar um computador novo:**
1. No computador novo, a pessoa clica em **Enviar pedido por e-mail**. O pedido chega em
   `scybersuporte@gmail.com`, com nome, unidade ou empresa e telefone.
2. Copie o pedido do e-mail. Pode ser **o e-mail inteiro**: clique no texto do e-mail, `Ctrl+A`,
   `Ctrl+C`. A tela acha sozinha o trecho que começa com `SCPM-PEDIDO-`, mesmo quebrado em várias
   linhas. Na tela, clique em **Colar**: ela mostra que é um pedido de ATIVAÇÃO e de qual computador.
3. Escolha a modalidade (**PM** ou **Business**) e preencha a unidade e, na Business, a empresa.
   A validade padrão é de 365 dias.
4. Clique em **Emitir licença**. A **resposta pronta** (instruções + chave) já fica copiada.
5. **Responda ao e-mail do pedido** e cole a resposta. No computador novo, a pessoa cola a chave na
   tela de ativação e clica em **Ativar**. **Não precisa de arquivo .sclic.** Se preferir mandar
   arquivo, use "Salvar arquivo .sclic…".

O e-mail de suporte fica num lugar só do código (`modLicenca.EMAIL_SUPORTE`). Para trocar, é preciso
uma versão nova do programa.

**Credenciar o certificado de uma pessoa:** o caminho é o mesmo, com o pedido de certificado. A tela
reconhece sozinha. Escolha **Usuário** ou **Revisor**, clique em **Credenciar certificado** e depois
em **Enviar ao GitHub**: o credenciamento só vale nos outros computadores depois de publicado.

**Listas:** a parte de baixo da tela mostra até quando as listas valem e fica vermelha quando faltam
10 dias ou menos. Para renovar, use **Renovar listas (+30 dias)** e depois **Enviar ao GitHub**.

**Enviar ao GitHub** faz o `git add/commit/push` só da pasta `licencas`. Ele só funciona numa pasta
que seja um clone do repositório (não num ZIP) e com o Git instalado. Se aparecer "rejected", rode
`git pull` na pasta do repositório e tente de novo.

Renovar, transferir, revogar e trocar administradores continuam pelos comandos abaixo.

## Conta de suporte: scybersuporte@gmail.com

Os pedidos de ativação e de certificado chegam a essa conta. Ela é um **canal oficial** do S-Cyber:
quem a controlar pode se passar pelo suporte. Por isso:

1. **Verificação em duas etapas** ligada (myaccount.google.com → Segurança), de preferência com
   app autenticador ou chave de acesso, não só por SMS.
2. **Recuperação:** um telefone e um e-mail de recuperação que só o titular controla.
3. **Senha** longa e exclusiva, que não seja usada em nenhum outro lugar.
4. **Mais de um atendente:** use a delegação do Gmail (Configurações → Contas → "Conceder acesso à
   sua conta"). Nunca compartilhe a senha.
5. **Filtro:** crie um filtro no Gmail com **Contém as palavras: `SCPM-PEDIDO`** que aplique um
   marcador, por exemplo "Pedidos S-Cyber". Filtre pelo texto, não pelo assunto: quem usa o Gmail no
   navegador cola o e-mail pronto no corpo, e o assunto pode chegar vazio.
6. **Golpes:** o suporte **nunca** pede senha, código de verificação nem arquivo de certificado
   (`.pfx`). A chave de ativação só serve para o computador que fez o pedido.

O endereço fica num lugar só do código (`modLicenca.EMAIL_SUPORTE`). Para trocar, é preciso gerar e
distribuir uma versão nova.

### Teste de ponta a ponta (depois de cada versão nova)
1. Instale a versão num computador ainda não ativado.
2. Clique em **Enviar pedido por e-mail** e confira se o e-mail chegou à conta de suporte.
3. Na tela do administrador, cole o pedido, emita a licença e responda ao e-mail com a resposta pronta.
4. No outro computador, cole a chave e clique em **Ativar**: deve aparecer "Instalação ativada".

## Preparação (uma vez)
Terminal: **Windows PowerShell**. Pasta: `S-Cyber-PM-Integrado` do repositório. Rode um comando por
vez.

```powershell
git pull
```

```powershell
.\.venv\Scripts\python.exe admin_licencas.py iniciar
```
Resultado esperado: `Administrador: SGT Gabriel Silveira Lima (certificado 7CB36ED1…)` e
`Listas criadas: ['administradores', 'revogacoes', 'credenciamentos']`.

```powershell
git add licencas ; git commit -m "Licenças: iniciar" ; git push
```
Resultado esperado: o push termina sem erro. A partir daí, os aplicativos baixam as listas do GitHub.

## Operações do dia a dia
Depois de **cada** operação, publique com o mesmo comando:
`git add licencas ; git commit -m "Licenças: <operação>" ; git push`.

**Emitir uma licença** (o usuário manda o *pedido de ativação*):
```powershell
.\.venv\Scripts\python.exe admin_licencas.py emitir --pedido "SCPM-PEDIDO-ATIVACAO.xxxx" --unidade "1º BPM" --dias 365 --saida licenca_1bpm.sclic
```
Resultado esperado: `Licença LIC-… para INST-…, válida até …`. Envie o arquivo `.sclic` ao usuário.
A emissão não muda as listas: a licença já funciona no outro computador sem publicar nada. Publicar
só guarda no GitHub o registro da operação.

**Emitir para uma empresa (S-Cyber Business):** a licença leva a modalidade e o nome da empresa. Os
dados dessa empresa ficam numa pasta só dela (`%APPDATA%\SCyberPM\perfis\<empresa>`), separados dos
dados da PM e de qualquer outra empresa no mesmo computador:
```powershell
.\.venv\Scripts\python.exe admin_licencas.py emitir --pedido "SCPM-PEDIDO-ATIVACAO.xxxx" --unidade "Loja Centro" --modalidade business --organizacao "Empresa Fictícia Ltda" --dias 365 --saida licenca_empresa.sclic
```
Sem `--organizacao`, vale o nome de `--unidade`. Renovar e transferir mantêm a modalidade e a empresa.

**Renovar** (com a licença atual do usuário):
```powershell
.\.venv\Scripts\python.exe admin_licencas.py renovar --chave licenca_1bpm.sclic --dias 365 --saida licenca_1bpm_renovada.sclic
```

**Transferir para outro computador** (a licença antiga é revogada na hora):
```powershell
.\.venv\Scripts\python.exe admin_licencas.py transferir --chave licenca_1bpm.sclic --pedido "SCPM-PEDIDO-ATIVACAO.yyyy" --saida licenca_nova.sclic
```

**Revogar**:
```powershell
.\.venv\Scripts\python.exe admin_licencas.py revogar --licenca LIC-XXXXXXXXXXXX --motivo "computador baixado"
```
A revogação vale na próxima abertura do programa com internet. Sem internet, vale em no máximo
**30 dias**, que é a validade da lista.

**Credenciar o certificado de um policial** (ele manda o *pedido de credenciamento*). Use
`--papel revisor` para quem pode encerrar achados:
```powershell
.\.venv\Scripts\python.exe admin_licencas.py credenciar --pedido "SCPM-PEDIDO-CERTIFICADO.zzzz" --papel usuario
```

**Descredenciar um certificado**:
```powershell
.\.venv\Scripts\python.exe admin_licencas.py descredenciar --thumbprint ABCD... --motivo "transferido"
```

**Republicar as listas** — obrigatório pelo menos a cada 3 semanas, porque as listas valem 30 dias.
Com a lista de revogações vencida, **nenhuma** instalação consegue conferir a licença. Por isso há
três avisos:
- o GitHub roda todo dia o workflow *Validade das listas de licença* e falha quando falta 10 dias
  ou menos. O GitHub avisa por e-mail;
- o diagnóstico do aplicativo mostra a validade e, a partir de 10 dias, pede para avisar o
  administrador;
- o `verificar` mostra `AVISO` a partir de 10 dias.
```powershell
.\.venv\Scripts\python.exe admin_licencas.py publicar
```

**Conferir tudo o que está publicado** (não precisa do certificado):
```powershell
.\.venv\Scripts\python.exe admin_licencas.py verificar
```
Resultado esperado: uma linha `OK` para cada lista, com a data e os dias que faltam, e para o
registro. `AVISO` = vence em até 10 dias (republique); `ERRO` = assinatura inválida ou lista vencida.

**Pasta de um ZIP (sem Git):** se a ferramenta rodar numa pasta baixada como ZIP, ela avisa que o
`git push` não funciona ali. Copie a pasta `licencas` para um clone do repositório e publique de lá.

## Registro das operações
O arquivo `licencas/registro.jsonl` tem uma linha **assinada** por operação, com o administrador, a
data, a instalação, a operação e o identificador da licença. O comando `verificar` e o CI acusam
qualquer linha alterada.

## Recuperar uma conta administrativa
Se um de vocês perder o certificado (computador formatado, por exemplo), o outro autoriza o
certificado novo e retira o perdido:
```powershell
.\.venv\Scripts\python.exe admin_licencas.py administradores --adicionar NOVO_THUMBPRINT --nome "SGT Gabriel (novo)" --remover THUMBPRINT_PERDIDO
```
Um administrador não pode remover o próprio certificado. Se os dois certificados forem perdidos, só
uma versão nova do aplicativo, com as impressões digitais novas em `ADMINISTRADORES_FIXOS`
(`modLicenca.py`), restabelece a emissão.

## Limites desta solução
- Não há servidor próprio: o GitHub publica as listas assinadas. A integridade vem da assinatura,
  não do servidor.
- Quem desligar a internet continua usando o programa até a lista vencer (no máximo 30 dias).
- Para revogação imediata em qualquer circunstância, é preciso um serviço de validação on-line
  da PMGO.
- As credenciais das fontes (token do GitHub, chave do HIBP) ficam cifradas no banco do usuário que
  as configurou. A recomendação institucional é guardá-las num serviço da PMGO, que confira a sessão
  e faça as consultas em nome do usuário.
