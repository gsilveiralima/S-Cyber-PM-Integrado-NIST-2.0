# ==============================================================================
#  S-Cyber PM - Cryptography and Digital Certificate Framework
# ------------------------------------------------------------------------------
#  Arquivo     : gerarExe.py
#  Descrição   : Gera o executável único de distribuição (SCyberPM.exe) com o
#                PyInstaller
#  Tipo        : Script de build
#  Versão      : ver formAbout.APP_VERSAO (fonte única da versão)
#  Revisão     : 2026-11-15
#  Autores     : MAJ Daniel Medrado - PMGO
#                MAJ Leonidio Alves de Moraes Junior - PMGO
#                SGT Gabriel Silveira Lima - PMGO
#  Instituição : Polícia Militar do Estado de Goiás
#  Contato     : leonidio.moraes@goias.gov.br
#  Licença     : Proprietária - todos os direitos reservados (ver LICENSE)
#  Requisitos  : Python 3.11+ (64 bits), Windows 10/11, PyInstaller 6+
#  Codificação : UTF-8
# ------------------------------------------------------------------------------
#  Histórico de revisões
#    Versão  Data        Alteração
#    1.4     2026-11-15  Criação
#                        Arquivos do usuário em %APPDATA%\SCyberPM
#                        Embute a trilha sonora da Corujinha no .exe
# ==============================================================================
"""
S-Cyber PM - geração do executável único para distribuição.

    python -m pip install pyinstaller
    python gerarExe.py

Resultado: dist\\SCyberPM.exe - um único arquivo, sem console, com o ícone da
corujinha e as informações de versão do Windows (Propriedades > Detalhes)
tiradas do formAbout.py. Leva junto o Python, todos os módulos, a marca
d'água e as imagens da interface; o computador
de destino não precisa ter o Python instalado.

O que NÃO vai dentro do .exe (e por quê):
  - o certificado digital: fica no repositório do Windows de cada usuário;
  - o arquivo de opções (scyber_pm.opcoes): é criado em %APPDATA%\\SCyberPM
    na primeira execução, cifrado com a chave do certificado; por isso o .exe
    pode ficar em qualquer pasta, inclusive em C:\\Program Files;
  - o WebView2 Runtime: já vem no Windows 10/11 atualizado.

Os arquivos intermediários ficam em build_exe\\ (pode apagar depois).
"""

import sys
from pathlib import Path

PASTA = Path(__file__).resolve().parent
TRABALHO = PASTA / "build_exe"
DESTINO = PASTA / "dist"
NOME = "SCyberPM"


def gerar_icone(caminho):
    """Ícone .ico da corujinha, com os tamanhos que o Windows usa."""
    from modRibbon import imagem_icone
    imagem_icone("coruja", 256).save(
        caminho, sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128),
                        (256, 256)])


def gerar_versao(caminho):
    """Informações de versão do Windows (VS_VERSIONINFO) a partir do formAbout."""
    from formAbout import APP_AUTOR, APP_COPYRIGHT, APP_NOME, APP_SUBTITULO, APP_VERSAO
    numeros = [int(n) for n in APP_VERSAO.split(".")]
    numeros = tuple((numeros + [0, 0, 0, 0])[:4])

    def texto(s):
        return s.replace("'", "\\'")

    caminho.write_text(f"""# Gerado por gerarExe.py - não edite
VSVersionInfo(
  ffi=FixedFileInfo(filevers={numeros}, prodvers={numeros},
                    mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0,
                    date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('041604B0', [
      StringStruct('CompanyName', '{texto(APP_AUTOR)}'),
      StringStruct('FileDescription', '{texto(APP_NOME)} - {texto(APP_SUBTITULO)}'),
      StringStruct('FileVersion', '{APP_VERSAO}'),
      StringStruct('InternalName', '{NOME}'),
      StringStruct('LegalCopyright', '{texto(APP_COPYRIGHT)}'),
      StringStruct('OriginalFilename', '{NOME}.exe'),
      StringStruct('ProductName', '{texto(APP_NOME)}'),
      StringStruct('ProductVersion', '{APP_VERSAO}')])]),
    VarFileInfo([VarStruct('Translation', [0x0416, 1200])])
  ]
)
""", encoding="utf-8")


def main():
    try:
        import PyInstaller.__main__
    except ImportError:
        sys.exit("PyInstaller não instalado. Rode:  python -m pip install pyinstaller")

    TRABALHO.mkdir(exist_ok=True)
    icone = TRABALHO / "scyber_pm.ico"
    versao = TRABALHO / "versao.txt"
    gerar_icone(icone)
    gerar_versao(versao)

    PyInstaller.__main__.run([
        str(PASTA / "appSCyberPM.py"),
        "--name", NOME,
        "--onefile",                     # um único .exe
        "--windowed",                    # sem janela de console
        "--icon", str(icone),
        "--version-file", str(versao),
        # a marca d'água vai para a raiz da pasta temporária (sys._MEIPASS),
        # um dos lugares onde o appSCyberPM a procura
        "--add-data", f"{PASTA / 'watermark.png'}{';' if sys.platform == 'win32' else ':'}.",
        # Imagem da espiã que diz "Thank You!" na simulação ponta a ponta (formE2E)
        "--add-data", f"{PASTA / 'espia.png'}{';' if sys.platform == 'win32' else ':'}.",
        "--paths", str(PASTA),
        # Módulos importados só quando usados (painel NIST e troca de senha):
        # declarados para o PyInstaller não deixar nenhum de fora
        "--hidden-import", "formNISTIntelligence",
        "--hidden-import", "formTrocaSenha",
        "--hidden-import", "formExploreSEI",
        # Abertura (ativação, certificado, perfil) e senha vazada: importados na hora do uso
        "--hidden-import", "formAbertura",
        "--hidden-import", "modLicenca",
        "--hidden-import", "modPerfil",
        "--hidden-import", "modDiagnostico",
        "--hidden-import", "modSenhaVazada",
        # Listas assinadas pelos administradores (cópia inicial; o aplicativo atualiza on-line).
        # As ferramentas dos administradores (admin_licencas.py e a tela) NÃO vão no executável.
        "--add-data", f"{PASTA / 'licencas'}{';' if sys.platform == 'win32' else ':'}licencas",
        # Termos de Uso, Política de Privacidade e avisos/licenças de terceiros (tela "Termos")
        "--add-data", f"{PASTA / 'legal'}{';' if sys.platform == 'win32' else ':'}legal",
        "--hidden-import", "modTermos",
        "--exclude-module", "admin_licencas",
        "--exclude-module", "admin_licencas_tela",
        "--collect-submodules", "nist_intelligence",
        "--collect-submodules", "reportlab.graphics",
        "--distpath", str(DESTINO),
        "--workpath", str(TRABALHO / "trabalho"),
        "--specpath", str(TRABALHO),
        "--noconfirm",
        "--clean",
    ])
    print(f"\nPronto: {DESTINO / (NOME + '.exe')}")


if __name__ == "__main__":
    main()
