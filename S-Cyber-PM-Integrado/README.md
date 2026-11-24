# S-Cyber PM

**Cryptography and Digital Certificate Framework**<br>
Versão 1.4

Aplicativo desktop para fins didáticos e de pesquisa sobre certificados digitais, criptografia e recursos de segurança do Windows. Ele reúne gestão de certificados, validação de acesso, assinatura de documentos, relatórios em PDF e demonstrações práticas em uma interface gráfica baseada em Tkinter.

> **Acesso restrito:** software de uso interno da Polícia Militar do Estado de Goiás. A redistribuição depende de autorização institucional. Consulte a seção [Licença](#licença) antes de copiar ou distribuir qualquer parte.

## Funcionalidades

- Autenticação por certificado digital com desafio e resposta usando a chave privada do Windows.
- Login local com senha e suporte opcional a Windows Hello, como PIN ou biometria.
- Consulta e gestão de certificados instalados no repositório pessoal do Windows.
- Importação, exportação, remoção e inspeção das propriedades dos certificados.
- Assinatura e verificação de documentos.
- Geração de PDFs assinados digitalmente e protegidos por senha AES-256.
- Formulários com visual padronizado: faixa de cabeçalho preta com o botão **Fechar** no canto superior direito.
- Navegador seguro com motor próprio para texto/TLS e motor Microsoft Edge WebView2.
- Seleção de protocolos e cifras, além da verificação da revogação dos certificados dos sites.
- Demonstrações de criptografia ponta a ponta com Diffie-Hellman ou ML-KEM pós-quântico, HKDF e AES-256-GCM.
- Simulações didáticas de alocação de memória, armazenamento em disco e uso do processador.
- Cálculo de hash SHA-256 e compactação de arquivos em partes.
- Ferramentas de PDF em Python puro, todas com conferência de integridade página a página:
  - dividir por número de páginas, por tamanho máximo ou em N partes iguais;
  - extrair ou reordenar páginas (ex.: `1-3, 7, 10-12`) e remover páginas;
  - juntar vários PDFs em um só;
  - comprimir com perfis prontos ou opções próprias: recompressão sem perda, agrupamento de objetos (object streams) e, se desejado, imagens em JPEG com qualidade e resolução ajustáveis;
  - assinatura digital e senha opcionais, independentes uma da outra.
- Gerenciador de usuários, pesquisa de arquivos, integração com o SEI e ferramenta de rádio.
- Relatório do sistema da Corujinha: inventário do computador, avaliação de segurança cibernética e raspagem de dados com captura de páginas pelo Edge headless. Veja [Relatório de segurança da Corujinha](#relatório-de-segurança-da-corujinha).
- Simulação de monitoramento do próprio aplicativo, incluindo processos, tela, memória, arquivos, rede e linha do tempo.
- Assistente local de comandos em linguagem natural, sem conexão com um serviço externo.
- Tour narrado da interface com legendas e destaque visual dos recursos.

## Relatório de segurança da Corujinha

O relatório começa com um **resumo dos pontos de atenção**: cada problema encontrado aparece em uma linha marcada com `[!]`, repetida também junto do item correspondente. As verificações são **somente de leitura**. Nada é alterado no computador e nenhuma senha é lida, nem as de redes Wi-Fi.

| Área | O que é verificado |
|---|---|
| Antivírus | Produtos registrados na Central de Segurança; Microsoft Defender (tempo real, comportamento, proteção contra adulteração, assinaturas, nuvem, regras ASR, acesso controlado a pastas, exclusões) e ameaças detectadas nos últimos 30 dias |
| Rede e acesso remoto | Firewall por perfil; Área de Trabalho Remota e NLA; SMBv1 e assinatura SMB; WinRM, Registro Remoto, Telnet, FTP e SNMP; LLMNR e NetBIOS; portas abertas com o processo responsável; conexões com a internet; pastas compartilhadas |
| Sistema | BitLocker por unidade; UAC; proteção do LSA; WDigest; nível de autenticação NTLM; segurança baseada em virtualização, Credential Guard e HVCI; atualizações e reinício pendente; PowerShell 2.0, política de execução e registro de scripts; SmartScreen e AutoRun |
| Contas | Contas locais (Convidado, Administrador interno, contas sem senha, senhas antigas); membros do grupo Administradores; política de senha e de bloqueio; bloqueio de tela por inatividade |
| Persistência | Programas que iniciam com o Windows, tarefas agendadas de terceiros e serviços instalados, com detecção de comandos típicos de malware; serviços com caminho sem aspas; programas em execução sem assinatura digital válida |
| Indícios e exposição | Proxy, script PAC e arquivo `hosts`; autoridades certificadoras raiz instaladas pelo usuário; certificados pessoais vencidos ou a vencer; programas de acesso remoto instalados; eventos (falhas de logon, contas criadas, logs apagados, serviços novos, desligamentos inesperados); pendrives já conectados; redes Wi-Fi salvas sem senha |

Algumas consultas exigem Administrador, como o log de Segurança, as exclusões do Defender e a configuração SMB. Sem essa permissão, o relatório indica quais itens ficaram limitados. Como os outros arquivos da Corujinha, o relatório fica cifrado na pasta temporária da sessão e é apagado depois de gerar o PDF ou ao fechar o formulário.

## Requisitos

- Windows 10 ou Windows 11, 64 bits.
- Python 3.11 ou superior, caso execute a partir do código-fonte.
- PowerShell 5.1 e .NET Framework 4.6.2 ou superior (incluídos no Windows 10/11).
- Certificado digital autorizado pelo aplicativo, com a chave privada disponível no repositório **Pessoal** do usuário do Windows.
- Microsoft Edge WebView2 Runtime para usar a aba WebView do navegador.
- Microsoft Edge instalado para recursos que usam renderização headless.

## Instalação e execução

Clone o repositório e entre na pasta do projeto:

```powershell
git clone https://github.com/Leonidiojr/SCyber-PM.git
cd SCyber-PM
```

Crie e ative um ambiente virtual e instale as dependências:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python appSCyberPM.py
```

No Prompt de Comando, a ativação pode ser feita com `.venv\Scripts\activate.bat`.

O aplicativo usa recursos específicos do Windows e não é compatível com Linux ou macOS. Os arquivos temporários da sessão são criados em `%TEMP%\SCyberPM\sessao_<PID>` e removidos ao encerrar o programa.

Não inclua senhas, chaves privadas, certificados ou outros dados de acesso no repositório.

## Gerar o executável

Com o ambiente virtual ativado e as dependências instaladas:

```powershell
python -m pip install pyinstaller
python gerarExe.py
```

O executável de arquivo único será criado em `dist\SCyberPM.exe`. O certificado não é incluído no executável: cada usuário precisa ter o certificado autorizado instalado no repositório Pessoal do Windows.

Os arquivos intermediários ficam em `build_exe\`. O computador de destino não precisa ter Python, mas deve atender aos requisitos do aplicativo e ter o WebView2 Runtime para usar essa opção do navegador.

As opções e os dados de usuário são armazenados separadamente em `%APPDATA%\SCyberPM`.

## Principais atalhos

| Ação | Atalho |
|---|---|
| Opções | `Ctrl+O` |
| Gerenciador de usuários | `Ctrl+U` |
| Pesquisar arquivos | `Ctrl+F` |
| Hash SHA-256 | `Ctrl+H` |
| Compactar em partes | `Ctrl+P` |
| Ferramentas de PDF | `Ctrl+D` |
| Navegador seguro | `Ctrl+B` |
| Criptografia ponta a ponta | `Ctrl+E` |
| Rádio digital | `Ctrl+T` |
| Consulta ao SEI | `Ctrl+I` |
| Alocação de memória | `Ctrl+M` |
| Armazenamento em disco | `Ctrl+K` |
| Uso do processador | `Ctrl+R` |
| Espião | `Ctrl+Y` |
| Tour | `F2` |

## Estrutura do projeto

- `appSCyberPM.py` — inicialização, autenticação e janela principal.
- `form*.py` — formulários e ferramentas da interface.
- `mod*.py` — componentes sem interface: certificados, recursos compartilhados, impressão, áudio e outros. Entre eles:
  - `modPDFDividir.py` — leitor e gravador de PDF em Python puro (dividir, extrair, remover, juntar, comprimir e conferir);
  - `modPDFProtegido.py` — assinatura digital e senha AES-256 dos PDFs gerados.
- `gerarExe.py` — geração do executável com PyInstaller.
- `requirements.txt` — dependências Python.
- `watermark.png`, `logo.png` e `espia.png` — imagens utilizadas pela interface.

## Autoria

- MAJ Daniel Medrado — Polícia Militar do Estado de Goiás (PMGO)
- MAJ Leonidio Alves de Moraes Junior — PMGO
- SGT Gabriel Silvieira Lima — PMGO

Contato: [leonidio.moraes@goias.gov.br](mailto:leonidio.moraes@goias.gov.br)

## Licença

Uso interno da instituição. **É proibida a redistribuição sem autorização.** A publicação deste repositório no GitHub não concede licença para uso, cópia ou distribuição.
