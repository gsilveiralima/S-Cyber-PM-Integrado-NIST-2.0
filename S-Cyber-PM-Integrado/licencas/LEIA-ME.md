# Publicação das licenças do S-Cyber PM

Arquivos **assinados** pelos administradores (SGT Gabriel Silveira Lima e MAJ Leonídio) com a
ferramenta `admin_licencas.py`. O aplicativo baixa estes arquivos do GitHub a cada abertura e
confere a assinatura e quem assinou. Ninguém consegue alterá-los sem um certificado de
administrador.

| Arquivo | Conteúdo |
|---|---|
| `administradores.scsig` | impressões digitais dos certificados administrativos |
| `revogacoes.scsig` | licenças revogadas (válida por 30 dias: republique com `publicar`) |
| `credenciamentos.scsig` | certificados de policiais autorizados e o papel (usuário/revisor) |
| `registro.jsonl` | uma linha assinada por operação: administrador, data, instalação, operação e licença |

Não coloque aqui nomes completos nem dados pessoais além do necessário: o repositório é público.
