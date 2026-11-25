# Guia rápido — instalar e usar o S-Cyber PM no Windows 11

Este guia serve para quem vai **usar** o programa. Os administradores (SGT Gabriel e MAJ Leonídio)
têm um guia próprio: [ADMINISTRACAO_LICENCAS.md](ADMINISTRACAO_LICENCAS.md).

Você não precisa instalar Python, editar código nem cadastrar impressões digitais à mão.

## 1. Instalar
1. Abra a página **[Releases](https://github.com/gsilveiralima/S-Cyber-PM-Integrado-NIST-2.0/releases)** do repositório e baixe, da versão mais recente, o `SCyberPM-Setup-<versão>.exe` e o `SHA256SUMS.txt`. Confira o SHA-256 no PowerShell: `Get-FileHash .\SCyberPM-Setup-2.0.0.exe -Algorithm SHA256`.
2. Dê dois cliques no instalador. Ele não pede administrador: o programa vai para
   `%LOCALAPPDATA%\Programs\S-Cyber PM`.
3. O instalador ainda não é assinado. Se o Windows mostrar *"O Windows protegeu o computador"*,
   clique em **Mais informações** e depois em **Executar assim mesmo**.
4. Ao final, ficam no menu Iniciar três atalhos:
   - **S-Cyber PM**;
   - **S-Cyber PM - painel NIST**;
   - **S-Cyber PM - diagnóstico de abertura**.

## 2. Ativar a instalação (primeira abertura)
1. Abra o programa pelo atalho **S-Cyber PM**. Aparece a tela **Ativação do S-Cyber PM**, com o número
   da instalação (`INST-…`).
2. Clique em **Enviar pedido por e-mail**. O e-mail para o suporte (`scybersuporte@gmail.com`) abre
   pronto. Complete nome, unidade ou empresa e telefone, e envie. Se você usa o e-mail só no navegador
   (Gmail, Outlook na web) e nada abriu, o e-mail inteiro já está copiado: escreva para o suporte e cole.
3. O suporte responde com uma **chave de ativação** (um texto que começa com `SCPM1.`). Cole a chave
   na tela ou, se recebeu um arquivo `.sclic`, use **Abrir arquivo .sclic…**.
4. Clique em **Ativar**. A licença fica vinculada a esta instalação e a este computador.

Para verificar se a licença foi revogada, o programa consulta a internet a cada abertura. Sem internet,
ele usa a última lista conferida por até 30 dias.

## 3. Certificado digital (cada pessoa, em cada conta do Windows)
1. Se a conta ainda não tiver um certificado autorizado, aparece a tela **Certificado digital** com
   a lista dos certificados da conta e a situação de cada um.
2. Clique em **Criar meu certificado…** e informe seu nome e posto. O programa cria o certificado
   com a chave privada **não exportável** e copia o **pedido de credenciamento**.
3. Envie o pedido ao administrador. Depois do aviso dele, clique em **Verificar novamente**.
4. No primeiro acesso, crie as suas senhas (não existe senha de fábrica). Cada senha precisa:
   - ter 12 ou mais caracteres;
   - misturar pelo menos 3 tipos de caractere;
   - não aparecer em vazamentos públicos (o programa confere no Pwned Passwords).

## 4. Usar o NIST a partir de um ativo
Use a aba **Ativos e achados**:
1. **Cadastre o ativo** com nome, tipo e identificador (nome do computador, domínio ou `dono/repositório`).
   Para software, informe também fabricante, produto e versão.
2. **Consulte uma fonte** com o ativo selecionado:
   - *CVE no CISA KEV* ou *KEV pelo fabricante/produto*;
   - *HIBP: catálogo público*;
   - *GitHub: secret scanning*, que só funciona em ativo autorizado e com o token configurado.

   A coleta técnica também gera achados para o computador cadastrado com o mesmo nome.
3. Selecione o achado e escolha:
   - **Descartar…**, informando o motivo;
   - ou **Confirmar…**, informando o resultado do CSF 2.0 (ex.: `ID.RA-01`), a prioridade com
     justificativa, o responsável, o prazo e a ação. Para o KEV, informe também o link do boletim do
     fabricante que você conferiu.
4. O responsável usa **Registrar correção…** e anexa a evidência.
5. Um **revisor** usa **Aprovar** ou **Devolver…**. Quem registrou a correção não pode revisá-la.
6. A aba **Painel** mostra as pendências: ações vencidas, divergências e correções aguardando
   verificação. Clique duas vezes numa pendência para abrir o achado.

## 5. Se algo der errado
- Use o atalho **S-Cyber PM - diagnóstico de abertura**. Ele grava um relatório na Área de Trabalho e
  o abre no Bloco de Notas. O relatório mostra:
  - a versão e a pasta do programa;
  - a pasta de dados;
  - os certificados da conta e a situação de cada um;
  - os arquivos cifrados e qual certificado abre cada um;
  - a **próxima ação**.
- Se aparecer *"Perfil cifrado com outro certificado"*, abra o **assistente de perfil**:
  - **Se o certificado antigo ainda está nesta conta:** use **Migrar para o certificado atual**. A
    migração faz uma cópia, confere registro a registro, testa a restauração e só então troca os
    arquivos. Os originais ficam em `%APPDATA%\SCyberPM\arquivo`.
  - **Se o certificado antigo não está mais disponível:** nada é apagado. Um perfil novo só é criado se
    você digitar `NOVO PERFIL`.
- **Licença vencida, revogada ou transferida:** na tela de ativação, use **Recuperar meus dados
  (sem licença)**. Você precisa do certificado e da senha de acesso. O programa exporta:
  - o backup cifrado do banco NIST;
  - as planilhas CSV;
  - um `MANIFESTO.txt` com o SHA-256 de cada arquivo.

  A licença controla o uso do programa, não a posse dos seus dados.
- Mantenha **uma só cópia** do programa. O diagnóstico avisa quando há duas cópias usando o mesmo perfil.

## 6. Atualizar e desinstalar
- **Atualizar:** rode o instalador novo por cima do atual. A ativação e os dados continuam.
- **Desinstalar:** use *Configurações > Aplicativos > S-Cyber PM > Desinstalar*. Isso remove só o programa.
  Os dados ficam guardados, em `%APPDATA%\SCyberPM` e em `%LOCALAPPDATA%\SCyberPM`.
