# S-Cyber PM — Cópia integrada ao NIST Intelligence (v0.5.0)

## Escopo

Cópia derivada do ZIP `S-Cyber-prj-main.zip`, desenvolvida em conjunto pelo MAJ Leonídio e pelo
SGT Gabriel para uso autorizado nos sistemas da PMGO. O repositório `Leonidiojr/S-Cyber-prj` não foi
modificado. O manifesto em `docs/MANIFESTO_ATUALIZACAO_CERTIFICADO.json` registra os arquivos da
v0.3.1. A partir da preparação para produção (`docs/PRODUCAO_SEGURANCA.md`), `appSCyberPM.py`,
`formOpcoes.py` e `formLogin.py` também foram alterados, e foi criado o `formTrocaSenha.py`.

## O que foi integrado

- Menu **NIST Intelligence** na aplicação principal.
- Aba **NIST Intelligence** na Ribbon com **Painel NIST CSF** e **Tela inicial**.
- Atalho **Ctrl+Shift+N** e comando do assistente local.
- Painel NIST embutido na área central (mesmo processo e mesmo Tk), sem segundo `Tk()`.
  Abas: Painel, Avaliação CSF 2.0, Plano de ação, Coleta técnica, Riscos, Incidentes,
  Evidências e custódia, OSINT, Consultas SEI e Relatório. Veja `GUIA_NIST_INTELLIGENCE.md`.
- Persistência própria da extensão em `%APPDATA%\SCyberPM\nist\nist.db` (o banco antigo de `%USERPROFILE%\SCyberNISTIntelligence` é copiado na primeira abertura).
- Consulta SEI opcional, sujeita a credenciais próprias e confirmação de autorização.
  Consulta não executada nem homologada com sistemas reais durante a preparação.

## Requisitos

- Windows 10/11 x64, Python >=3.11, dependências do `requirements.txt` original.
- Certificado autorizado e login do S-Cyber PM para acesso à janela principal.
- `requests` já está no `requirements.txt` original para o SEI.

## Executar (PowerShell, dentro desta pasta)

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python appSCyberPM.py
```

Se a política do Windows bloquear a ativação, use ` .\.venv\Scripts\python.exe appSCyberPM.py `
sem ativar o ambiente.

Após o login autorizado: menu/ribbon **NIST Intelligence** ou **Ctrl+Shift+N**.
Para sair do painel, use **Tela inicial**.

### Verificação independente do painel (sem login principal)

```powershell
$env:SCYBER_NIST_DEV=1; .\.venv\Scripts\python.exe teste_painel_nist.py
```

Esse teste abre apenas a extensão; não habilita as ferramentas nem contorna o
certificado ou login do S-Cyber PM.

## Limitações de segurança e implantação

A cópia preserva características do código original, incluindo credenciais de
exemplo e configuração de validação de certificados já existentes. Isso exige
revisão e autorização institucional antes de uso em produção.

- O SQLite da extensão **não cifra** os dados em repouso.
- Não registrar dados pessoais, sigilosos, policiais ou de inteligência na extensão
  até aprovação e implantação dos controles adequados.
- A consulta SEI é sob demanda, somente leitura, não grava credenciais em banco
  local e bloqueia redirecionamentos fora da origem HTTPS configurada.
- Nenhuma consulta real ou teste de acesso institucional foi realizado.
- Executável PyInstaller não foi gerado: a execução validada desta entrega é via
  código-fonte; a empacotagem do EXE precisa ser testada em Windows.

## Alterações específicas na cópia

- **Modificado:** `appSCyberPM.py` (menu, ribbon, assistente, view embutida).
- **Criados:** `formNISTIntelligence.py`, pacote `nist_intelligence/`,
  `teste_painel_nist.py`, `INSTRUCOES_INTEGRACAO.md`.
- **Preservados:** outros arquivos fonte e assets necessários, sem incluir binários
  pré-compilados, pastas de build, caches do IDE ou certificado em `dist/`.


## Correção de correspondência de certificado (v0.3.1)

Antes de abrir o aplicativo, consulte `CERTIFICADO_ORIGINAL_VERIFICACAO.md`. O thumbprint de `appSCyberPM.py` foi alinhado ao certificado público enviado com o ZIP original. É obrigatória a chave privada correspondente no repositório pessoal do Windows.
