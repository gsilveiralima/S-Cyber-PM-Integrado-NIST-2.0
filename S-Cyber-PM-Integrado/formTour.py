# ==============================================================================
#  S-Cyber PM - Cryptography and Digital Certificate Framework
# ------------------------------------------------------------------------------
#  Arquivo     : formTour.py
#  Descrição   : Tour narrado (modo demonstração): abre e explica cada
#                formulário com voz feminina e legendas
#  Tipo        : Formulário (tkinter)
#  Versão      : ver formAbout.APP_VERSAO (fonte única da versão)
#  Revisão     : 2026-11-16
#  Autores     : MAJ Daniel Medrado - PMGO
#                MAJ Leonidio Alves de Moraes Junior - PMGO
#                SGT Gabriel Silveira Lima - PMGO
#  Instituição : Polícia Militar do Estado de Goiás
#  Contato     : leonidio.moraes@goias.gov.br
#  Licença     : Proprietária - todos os direitos reservados (ver LICENSE)
#  Requisitos  : Python 3.11+ (64 bits), Windows 10/11, pywin32
#  Codificação : UTF-8
# ------------------------------------------------------------------------------
#  Histórico de revisões
#    Versão  Data        Alteração
#    1.4     2026-11-15  Criação
#                        Contorno vermelho e fundo em preto e branco
#                        Narradora aceita outro idioma (voz em inglês da Eva)
#                        Narração da Corujinha cita a raspagem de dados
#                        Narração da Corujinha cita a imagem da página
#                        Narração da Corujinha cita a pesquisa no site
#                        Passo do Espião no roteiro
#                        Narração da Corujinha: trabalho escondido e protegido contra captura
#                        Narração do Espião: linha do tempo e PDF
#                        Narração da Corujinha cita o inventário do PC
#            2026-11-16  Botão Encerrar no canto superior direito do cabeçalho
#            2026-11-21  Voz sai no dispositivo de áudio padrão do Windows
# ==============================================================================
"""
S-Cyber PM - Formulário formTour: modo demonstração narrado (Arquivo > Tour).

Uma narradora apresenta o aplicativo passo a passo: aponta o botão na Ribbon,
abre o formulário, explica o que ele faz e quais tecnologias usa, e fecha o
formulário ao passar para o próximo passo. O texto falado aparece também
como legenda, para quem estiver sem som.

VOZ: a síntese de fala do Windows (SAPI 5), pelo pywin32 - a mesma voz que o
Narrador do Windows pode usar. A narradora escolhe, nesta ordem: uma voz
feminina em português do Brasil (ex.: Microsoft Maria), qualquer voz em
português, qualquer voz feminina, a primeira voz instalada. Sem nenhuma voz,
o Tour segue só com as legendas, no tempo estimado de leitura.

DESTAQUE: um contorno vermelho cerca o ícone e, depois, o formulário do passo,
e o resto da tela fica em preto e branco (modDestaque.py). Os cliques
continuam funcionando normalmente; a opção pode ser desligada na janela.

Controles: Anterior, Pausar/Continuar, Próximo, Encerrar e "Avançar sozinho";
teclas ← → (passos), espaço (pausa) e Esc (encerra).

O Tour NÃO executa ações: só abre os formulários para mostrar a tela. A
Corujinha (que abre o PowerShell e usa a câmera) é apenas apontada e explicada.

Uso dentro da aplicação:
    from formTour import FormTour
    FormTour(root, ribbon=ribbon, status=status, acoes={"opcoes": abrir_opcoes, ...})
"""

import time
import tkinter as tk
from dataclasses import dataclass
from tkinter import ttk

from modDestaque import Destaque
from modRecursos import botao_fechar_cabecalho
from modRibbon import foto_icone

# SAPI 5 (SpeechVoiceSpeakFlags / SpeechRunState)
SAPI_ASSINCRONO = 1
SAPI_DESCARTAR_ANTERIOR = 2
SAPI_FALANDO = 2
LINGUA_PT_BR = "416"                    # LCID do português do Brasil, em hexadecimal
LINGUA_EN_US = "409"                    # inglês dos EUA

PAUSA_ENTRE_PASSOS_MS = 1500            # silêncio antes de avançar sozinho
PALAVRAS_POR_SEGUNDO = 2.6              # tempo estimado das legendas sem voz

# Como a narradora deve LER alguns termos (a legenda continua com a grafia normal)
PRONUNCIA = [
    ("S-Cyber PM", "Ésse Sáiber, pê ême"),
    ("S-Cyber Business", "Ésse Sáiber Bízness"),
    ("PMGO", "pê ême gê ó"),
    ("PDFs", "pê dê éfes"),
    ("PDF", "pê dê éfe"),
    ("SHA-256", "chá 256"),
    ("AES-256-GCM", "A É Ésse 256, G C M"),
    ("AES-256", "A É Ésse 256"),
    ("AES", "A É Ésse"),
    ("PKCS #7", "P K C S sete"),
    ("PBKDF2", "P B K D F 2"),
    ("HKDF", "H K D F"),
    ("ML-KEM", "M L Kém"),
    ("X.509", "X 509"),
    ("TLS", "T L S"),
    ("CMS", "C M S"),
    ("RSA", "R S A"),
    ("NIST", "Nist"),
    ("CSF", "C S F"),
    ("LGPD", "L G P D"),
    ("ANPD", "A N P D"),
    ("OSINT", "ósint"),
    ("CSV", "C S V"),
    ("BitLocker", "Bit Locker"),
    ("SMBv1", "S M B versão 1"),
    ("RDP", "R D P"),
    ("SEI", "Séi"),
    ("GIL", "Guil"),
    ("RAM", "Râm"),
    (".p7s", "ponto p 7 s"),
    ("%APPDATA%", "a pasta de dados do usuário"),
]


# ==========================================================
# NARRADORA (SAPI)
# ==========================================================

class Narradora:
    """Voz do Tour. Se a fala não estiver disponível, .ativa fica False e o
    motivo vai em .aviso; os demais métodos passam a não fazer nada."""

    def __init__(self, lingua=LINGUA_PT_BR):
        """lingua: LCID em hexadecimal da voz preferida (LINGUA_PT_BR, LINGUA_EN_US...)."""
        self.voz = None
        self.nome = None
        self.aviso = None
        self._pausada = False
        try:
            import win32com.client
            self.voz = win32com.client.dynamic.Dispatch("SAPI.SpVoice")
            vozes = list(self.voz.GetVoices())
        except Exception as e:  # noqa: BLE001 - sem pywin32, sem SAPI ou sem áudio
            self.voz = None
            self.aviso = f"Fala indisponível ({type(e).__name__}): o Tour segue só com legendas."
            return
        if not vozes:
            self.voz = None
            self.aviso = "Nenhuma voz instalada no Windows: o Tour segue só com legendas."
            return

        def nota(v):
            feminina = v.GetAttribute("Gender") == "Female"
            no_idioma = lingua in (v.GetAttribute("Language") or "").split(";")
            return (feminina and no_idioma) * 4 + no_idioma * 2 + feminina

        escolhida = max(vozes, key=nota)
        self.voz.Voice = escolhida
        self.nome = escolhida.GetDescription()
        self._saida_padrao_do_windows()
        if nota(escolhida) < 4:
            idioma = "português" if lingua == LINGUA_PT_BR else f"idioma {lingua}"
            self.aviso = (f"Voz feminina em {idioma} não encontrada; usando "
                          f"\"{self.nome}\". Instale em Configurações > Hora e idioma > Fala.")

    def _saida_padrao_do_windows(self):
        """O SAPI fala na saída escolhida no painel de Fala (ou na primeira que
        enumerar), que pode ser uma saída sem alto-falante, como a digital/óptica.
        O wave mapper (DeviceId -1) segue o dispositivo padrão do Windows."""
        try:
            import win32com.client
            saida = win32com.client.dynamic.Dispatch("SAPI.SpMMAudioOut")
            saida.DeviceId = -1                  # WAVE_MAPPER
            self.voz.AllowAudioOutputFormatChangesOnNextSet = False
            self.voz.AudioOutputStream = saida
        except Exception:  # noqa: BLE001 - mantém a saída configurada no SAPI
            pass

    @property
    def ativa(self):
        return self.voz is not None

    @staticmethod
    def pronuncia(texto):
        for escrito, falado in PRONUNCIA:
            texto = texto.replace(escrito, falado)
        return texto

    def falar(self, texto):
        if not self.ativa:
            return
        self.continuar()                         # falar estando em pausa travaria a fila
        self.voz.Speak(self.pronuncia(texto), SAPI_ASSINCRONO | SAPI_DESCARTAR_ANTERIOR)

    def calar(self):
        if self.ativa:
            self.continuar()
            self.voz.Speak("", SAPI_ASSINCRONO | SAPI_DESCARTAR_ANTERIOR)

    def pausar(self):
        if self.ativa and not self._pausada:
            self.voz.Pause()
            self._pausada = True

    def continuar(self):
        if self.ativa and self._pausada:
            self.voz.Resume()
            self._pausada = False

    def falando(self):
        return self.ativa and self.voz.Status.RunningState == SAPI_FALANDO

    def velocidade(self, valor):
        if self.ativa:
            self.voz.Rate = max(-10, min(10, int(valor)))


# ==========================================================
# ROTEIRO
# ==========================================================

@dataclass
class Passo:
    titulo: str
    texto: str                    # falado e mostrado como legenda
    tecnologias: str = ""
    destaque: str = None          # ícone do botão a apontar na Ribbon
    acao: str = None              # chave em 'acoes' (abre um formulário) ou ação interna


ROTEIRO = [
    Passo("Boas-vindas",
          "Olá! Eu sou a narradora do Tour do S-Cyber PM, um exemplo didático de "
          "criptografia e certificados digitais, desenvolvido na Polícia Militar do Estado "
          "de Goiás para fins de ensino e pesquisa. Nos próximos minutos, vou abrir cada "
          "formulário e explicar, de forma simples, o que ele faz e quais tecnologias usa. "
          "Você pode pausar, voltar ou avançar a qualquer momento, nos botões desta janela.",
          "Python 3.11 · Tkinter · síntese de fala do Windows (SAPI)", destaque="tour"),
    Passo("Como você entrou: certificado e senha",
          "Antes desta tela aparecer, o aplicativo conferiu quem você é, em duas etapas. "
          "Na tela de abertura, houve um desafio e resposta com o certificado digital: o "
          "programa sorteou um número aleatório e pediu ao Windows que o assinasse com a "
          "chave privada do certificado. Só quem possui essa chave consegue produzir a "
          "assinatura, e a conferência é feita com a chave pública. Depois veio o login, em "
          "que a senha nunca é guardada: fica apenas um resumo dela, calculado trezentas mil "
          "vezes com PBKDF2, para dificultar ataques de força bruta.",
          "RSA PKCS #1 v1.5 · SHA-256 · desafio de 32 bytes · PBKDF2-HMAC-SHA256"),
    Passo("A janela principal",
          "Esta é a janela principal. No topo fica a barra, com uma aba para cada "
          "menu: Arquivo, Certificados, Ferramentas e Ajuda. Os ícones dos botões são "
          "desenhados pelo próprio programa, sem arquivos de imagem. Embaixo, a barra de "
          "status mostra mensagens, a data, a hora, o endereço IP e o nome deste computador.",
          "Tkinter · Pillow (ícones desenhados em código) · API do Windows",
          acao="percorrer_ribbon"),
    Passo("Opções",
          "Em Arquivo, Opções, você define a senha dos PDFs exportados e a senha de acesso. "
          "Essas configurações ficam num arquivo criptografado com AES-256-GCM, na pasta do "
          "usuário. A chave desse arquivo é derivada do próprio certificado digital: sem a "
          "chave privada, ninguém consegue abri-lo, e qualquer alteração é detectada.",
          "AES-256-GCM · HKDF · %APPDATA%\\SCyberPM", destaque="opcoes", acao="opcoes"),
    Passo("Certificados digitais",
          "Este é o gerenciador de certificados. Ele lista os certificados instalados no "
          "Windows, com as propriedades do padrão X.509: titular, emissor, validade, "
          "impressão digital e usos da chave. Também permite importar, exportar e excluir "
          "certificados, e gerar um relatório em PDF.",
          "X.509 v3 · PKCS #12 · PEM e DER · repositório de certificados do Windows",
          destaque="certificado", acao="certificados"),
    Passo("Assinatura de documentos",
          "Aqui você assina qualquer documento com o certificado. A assinatura é destacada, "
          "no padrão CMS, também chamado PKCS #7: o documento não muda, e a assinatura vai "
          "para um arquivo ao lado, com a extensão .p7s. Se um único byte do documento for "
          "alterado, a verificação acusa na hora.",
          "CMS / PKCS #7 (RFC 5652) · SHA-256 · SignedCms do .NET",
          destaque="assinar", acao="assinar"),
    Passo("PDFs sempre protegidos",
          "Uma regra vale para todo o aplicativo: nenhum PDF sai sem proteção. Cada relatório "
          "exportado é criptografado com AES-256 e só abre com a senha definida nas Opções. "
          "Além disso, recebe uma assinatura digital embutida, que o leitor de PDF mostra no "
          "painel de assinaturas e que prova que o documento não foi alterado.",
          "ISO 32000-2 (AES-256, revisão 6) · assinatura adbe.pkcs7.detached"),
    Passo("Usuários do Windows",
          "O gerenciador de usuários lista as contas locais do Windows, com um gráfico e um "
          "relatório em PDF. Ações como bloquear uma conta ou trocar a senha exigem "
          "privilégios de administrador, e o programa avisa quando isso for preciso.",
          "PowerShell (Get-LocalUser) · matplotlib · reportlab",
          destaque="usuarios", acao="usuarios"),
    Passo("Corujinha",
          "A Corujinha gera um relatório do sistema que começa com um inventário completo "
          "do computador - identificação, sistema, processador, placa-mãe, memória, discos, "
          "vídeo e rede - e depois verifica o disco, os arquivos do "
          "System32 e os dispositivos de rede com o PowerShell, em segundo plano e sem "
          "janelas, enquanto a coruja fica na frente, protegida contra captura de tela. Ao mesmo "
          "tempo, faz a raspagem de dados de um artigo da Wikipédia: baixa a página e extrai "
          "do HTML a ficha técnica, o resumo e as seções, e fotografa a página com o Edge "
          "sem janela. Depois, como faria uma pessoa, acha o campo de pesquisa do site, "
          "busca por Leonardo Fibonacci e repete a raspagem no artigo encontrado. Tudo vai "
          "para um relatório com capturas da tela e da câmera. Por usar a câmera, ela não é "
          "aberta automaticamente neste Tour; fica só a apresentação.",
          "PowerShell sem janelas · proteção contra captura · raspagem de dados · Edge headless",
          destaque="coruja"),
    Passo("Pesquisa de arquivos",
          "A pesquisa de arquivos procura por nome, extensão, tamanho e data, sem travar a "
          "janela, porque a busca roda numa linha de execução separada. O resultado pode ser "
          "exportado em PDF, que sai protegido como todos os outros.",
          "threading · varredura de pastas · reportlab", destaque="pesquisar", acao="pesquisa"),
    Passo("Hash de arquivos",
          "Um hash é a impressão digital de um arquivo: qualquer mudança, por menor que "
          "seja, gera um resultado completamente diferente. Este formulário calcula o SHA-256 "
          "de vários arquivos e confere com valores publicados, no mesmo formato dos "
          "utilitários sha256sum.",
          "SHA-256 (FIPS 180-4) · hashlib", destaque="hash", acao="hash"),
    Passo("Compactar em partes",
          "Para arquivos grandes demais para um pen drive ou um e-mail, este formulário "
          "compacta o arquivo e o divide em partes do tamanho escolhido. Logo depois, faz um "
          "teste de extração: remonta tudo numa pasta temporária e confere o SHA-256 com o "
          "original, para você saber que as partes abrem antes de distribuí-las.",
          "LZMA / zlib · manifesto JSON · SHA-256", destaque="particionar", acao="particionar"),
    Passo("Dividir PDF",
          "Aqui um PDF é dividido por número de páginas ou por tamanho. O leitor de PDF foi "
          "escrito em Python puro, sem bibliotecas externas. Cada parte é relida e comparada "
          "página a página com o original, e só então recebe assinatura e senha.",
          "leitor de PDF próprio · conferência de integridade · ISO 32000",
          destaque="dividir_pdf", acao="dividir_pdf"),
    Passo("Navegador seguro",
          "O navegador seguro tem duas abas. Na primeira, um motor próprio, em texto, em que "
          "você escolhe exatamente os protocolos e as cifras aceitos, e vê a cadeia de "
          "certificados do site e a revogação. Na segunda, o motor do Microsoft Edge, com "
          "política mínima de TLS. Neste Tour ele abre em branco: nenhuma página é "
          "carregada até você digitar um endereço.",
          "TLS 1.3 e 1.2 · OCSP e CRL · WebView2", destaque="navegador", acao="navegador"),
    Passo("Criptografia de ponta a ponta",
          "Esta é uma simulação animada de criptografia de ponta a ponta. Alice e Bob trocam "
          "chaves com Diffie-Hellman ou com o algoritmo pós-quântico ML-KEM, derivam uma "
          "chave com HKDF e cifram a mensagem com AES-256-GCM. A mensagem passa pela área de "
          "transferência do Windows, que faz o papel do servidor: ela só enxerga dados cifrados.",
          "X25519 · ML-KEM (FIPS 203) · HKDF · AES-256-GCM", destaque="e2e", acao="e2e"),
    Passo("SEI",
          "O formulário do SEI entra no Sistema Eletrônico de Informações com o seu usuário e "
          "a sua senha, como um navegador faria, e mostra os processos da sua unidade e uma "
          "pesquisa rápida por número.",
          "HTTP com sessão e cookies (requests) · leitura de HTML", destaque="sei", acao="sei"),
    Passo("Memória: recursão",
          "Agora, três demonstrações sobre os recursos do computador. A primeira mostra como "
          "a recursão consome memória: cada chamada aloca um bloco de RAM e chama a si mesma. "
          "Um piso de segurança impede que o computador fique instável.",
          "recursão · GlobalMemoryStatusEx", destaque="memoria", acao="memoria"),
    Passo("Disco: gravação e cache",
          "A segunda faz o mesmo com o disco: cada chamada grava um bloco, força a gravação "
          "física e mede a velocidade. No fim, tudo é lido de volta e conferido com SHA-256, "
          "e você vê, na prática, a diferença entre o cache na memória e o disco de verdade.",
          "fsync · cache de arquivos do Windows · SHA-256", destaque="disco", acao="disco"),
    Passo("Processador: processos e threads",
          "A terceira coloca carga no processador, com Fibonacci recursivo. Compare os dois "
          "modos: com processos, cada trabalhador ocupa um núcleo; com threads, o GIL do "
          "Python deixa só uma executar por vez. Os trabalhadores rodam na prioridade ociosa, "
          "então o computador continua respondendo.",
          "multiprocessing · GIL · NtQuerySystemInformation",
          destaque="processador", acao="processador"),
    Passo("Espião: o olhar do invasor",
          "Por fim, o Espião faz contra o próprio aplicativo o que um programa espião na mesma "
          "conta faria: lista os processos e decodifica as linhas de comando, fotografa a tela, "
          "lê a memória e os arquivos, e acompanha a rede. E mostra o placar: os arquivos "
          "temporários estão cifrados e uma cópia não abre sem o segredo da execução, nenhum "
          "script fica no disco e as conexões externas usam TLS. Uma linha do tempo no rodapé "
          "mostra tudo o que foi acontecendo, e o botão Gerar PDF salva o relatório com as "
          "imagens e os dados coletados, assinado e protegido por senha como os demais. Também "
          "deixa claros os limites: a tela e a área de transferência podem ser lidas por qualquer "
          "programa.",
          "WMI (Win32_Process) · EnumWindows · entropia de Shannon · DPAPI · TLS · reportlab",
          destaque="espiao", acao="espiao"),
    Passo("NIST Intelligence: o que é e como abrir",
          "Agora vem a extensão de governança do aplicativo: o S-Cyber NIST Intelligence. Ele "
          "ajuda a medir e melhorar a segurança cibernética da sua unidade usando o NIST "
          "Cybersecurity Framework 2.0, o Nist CSF, um padrão internacional organizado em seis "
          "funções: Governar, Identificar, Proteger, Detectar, Responder e Recuperar. Para abrir, "
          "use a aba NIST Intelligence da Ribbon, no botão Painel NIST CSF, o menu NIST "
          "Intelligence, ou o atalho Control Shift N. O painel abre dentro desta mesma janela, "
          "e o botão Voltar à tela principal, no canto superior, leva você de volta. Os dados "
          "ficam num banco local cifrado, com chave derivada do seu certificado digital: sem o "
          "certificado, ninguém abre. Ele tem dez abas, que vou mostrar agora, na ordem em que "
          "normalmente se usam.",
          "NIST CSF 2.0 · SQLite cifrado · AES-256-GCM · HKDF · Tkinter",
          destaque="nist", acao="nist"),
    Passo("NIST: aba Painel",
          "A aba Painel é o resumo da situação. Cada cartão representa uma função do Nist CSF "
          "e mostra a maturidade média, de zero a quatro, o alvo desejado e quantas "
          "subcategorias já foram avaliadas. O gráfico compara a maturidade atual com o perfil-"
          "alvo, e a lateral lista os alertas, como prazos vencendo. Use esta aba para ter a "
          "visão geral e saber onde estão as maiores lacunas. Lembre-se: subcategoria ainda não "
          "avaliada conta como zero, então o painel melhora conforme você avalia.",
          "Canvas do Tkinter · maturidade 0–4", acao="nist_aba:Painel"),
    Passo("NIST: aba Avaliação CSF 2.0",
          "Aqui você faz o diagnóstico. À esquerda, a árvore com as funções, categorias e "
          "subcategorias do framework. Clique numa subcategoria, leia o texto oficial e "
          "informe a maturidade atual, a maturidade desejada, o responsável e o prazo; depois, "
          "clique em Salvar avaliação. Em Nível de implementação, defina o Tier de cada "
          "função, de um a quatro. A coluna Técnico mostra o resultado da última coleta "
          "automática ligada àquela subcategoria, e a coluna Evid. conta os arquivos anexados "
          "como prova: use Anexar arquivo novo, que guarda o SHA-256 na cadeia de custódia. O "
          "botão Exportar avaliação CSV gera uma planilha para análise externa.",
          "árvore hierárquica · perfil atual × perfil-alvo · Tiers · evidências · exportação CSV",
          acao="nist_aba:Avaliação CSF 2.0"),
    Passo("NIST: aba Plano de ação",
          "O plano de ação é gerado sozinho a partir das lacunas: toda subcategoria cujo alvo "
          "é maior que o nível atual vira uma tarefa. A prioridade é a lacuna multiplicada por "
          "dois quando a coleta técnica encontrou uma falha ligada àquela subcategoria, ou "
          "seja, o que está de fato errado neste computador sobe na fila. Clique duas vezes "
          "numa linha para editar a avaliação, e exporte o plano em CSV para acompanhar a "
          "execução.",
          "cálculo de prioridade · exportação CSV", acao="nist_aba:Plano de ação"),
    Passo("NIST: aba Coleta técnica",
          "A coleta técnica verifica este computador de forma automática e somente de leitura: "
          "antivírus, firewall, BitLocker, controle de contas, área de trabalho remota RDP, "
          "SMBv1, atualizações, contas locais, política de senhas, bloqueio de tela, logs, "
          "portas abertas e o certificado do S-Cyber PM. Clique em Executar verificação agora e "
          "aguarde até um minuto. Cada resultado é ligado às subcategorias do CSF e gravado com "
          "o SHA-256 dos dados coletados, para provar que não foi alterado. Nada é modificado "
          "no sistema. Para os computadores sem o S-Cyber PM, salve o coletor avulso, rode-o "
          "lá e importe o arquivo gerado: a avaliação considera a pior situação entre todos.",
          "PowerShell somente leitura · SHA-256 · vários computadores · mapeamento para o CSF",
          acao="nist_aba:Coleta técnica"),
    Passo("NIST: aba Riscos",
          "No registro de riscos, você cadastra cada risco com probabilidade e impacto, de um a "
          "três. O sistema calcula o risco inerente, multiplicando os dois, e o risco residual, "
          "depois do tratamento que você escolher: mitigar, transferir, aceitar ou evitar. O "
          "mapa de calor mostra onde os riscos se concentram. Clique num risco da lista para "
          "editar, use Novo para limpar o formulário e Exportar CSV para levar os dados.",
          "matriz ordinal 3×3 · mapa de calor · risco inerente e residual",
          acao="nist_aba:Riscos"),
    Passo("NIST: aba Incidentes",
          "Esta aba apoia a resposta a incidentes, nas funções Responder e Recuperar. Registre "
          "o incidente e marque se envolve dados pessoais: nesse caso, o prazo de comunicação "
          "à A N P D, de três dias úteis a partir do conhecimento, é calculado e acompanhado, "
          "descontando fins de semana, feriados nacionais e os feriados locais cadastrados em "
          "Feriados, e o botão Comunicado à A N P D hoje registra o cumprimento. Cada fase é lançada numa "
          "linha do tempo encadeada por hash, e o botão Verificar integridade denuncia qualquer "
          "alteração feita depois.",
          "LGPD · Res. CD/ANPD nº 15/2024 · cadeia de hashes", acao="nist_aba:Incidentes"),
    Passo("NIST: aba Evidências e custódia",
          "Aqui você preserva evidências digitais. Escolha o arquivo e clique em Selecionar "
          "arquivo e registrar: o sistema guarda o SHA-256 dele. Cada movimentação, como "
          "coleta, transferência ou análise, entra numa cadeia de custódia encadeada por hash. "
          "Reverificar recalcula o hash do arquivo no local registrado e avisa se ele mudou; "
          "Verificar cadeia confere todos os registros. A ferramenta apoia, mas não substitui, "
          "o procedimento pericial oficial.",
          "SHA-256 · cadeia de custódia · integridade", acao="nist_aba:Evidências e custódia"),
    Passo("NIST: aba OSINT",
          "O ósint defensivo é o registro e a triagem de informações públicas que expõem a "
          "sua organização, como vazamentos, perfis falsos ou dados em sites abertos. A "
          "pesquisa é manual: você encontra, registra o indício, a fonte e a gravidade, e "
          "pode excluir ou exportar em CSV. Todo achado exige revisão humana antes de virar "
          "ação.",
          "fontes abertas · triagem manual · exportação CSV", acao="nist_aba:OSINT"),
    Passo("NIST: aba Consultas SEI",
          "Consultas internas ao SEI, somente leitura. Informe o endereço da instância, seu "
          "usuário e sua senha, marque a confirmação de que tem autorização e clique em "
          "Conectar. Depois, pesquise processos pelo termo. As consultas não são gravadas no "
          "banco, e Desconectar encerra a sessão.",
          "HTTP com sessão (requests) · leitura de HTML", acao="nist_aba:Consultas SEI"),
    Passo("NIST: aba Consolidação",
          "A consolidação junta a situação de várias unidades. Cada unidade gera um pacote "
          "assinado com o próprio certificado e cifrado com uma senha combinada; a unidade "
          "consolidadora importa os pacotes, o sistema confere a assinatura e se o certificado "
          "está na lista de autorizados, e mostra a maturidade por função, os riscos altos e os "
          "prazos da A N P D de cada uma, com a média geral. Só vão dados minimizados, sem textos.",
          "assinatura CMS · scrypt + AES-256-GCM · minimização LGPD", acao="nist_aba:Consolidação"),
    Passo("NIST: aba Relatório",
          "Por fim, o relatório de governança em PDF: resumo por função com gráfico, plano de "
          "ação, mapa de calor de riscos, incidentes com o prazo da A N P D, evidências com a "
          "integridade da custódia e o resultado da coleta técnica. Informe a organização e o "
          "responsável, escolha se o PDF será assinado com o certificado do S-Cyber PM e "
          "protegido com a senha das Opções, e clique em Gerar relatório PDF. Na mesma aba ficam "
          "o backup, as cópias automáticas diárias e a retenção, que exclui incidentes encerrados "
          "há mais tempo que o prazo de guarda, sempre com backup antes e registro na auditoria.",
          "reportlab · assinatura PKCS #7 · AES-256 · retenção LGPD", acao="nist_aba:Relatório"),
    Passo("NIST: fluxo de uso recomendado",
          "Resumindo o uso do Nist Intelligence: primeiro, rode a Coleta técnica; segundo, "
          "avalie as subcategorias na aba de Avaliação; terceiro, consulte o Plano de ação "
          "para priorizar; quarto, registre riscos, incidentes e evidências conforme "
          "aparecerem; e quinto, gere o Relatório em PDF para apresentar à chefia. Repita o "
          "ciclo periodicamente e acompanhe a evolução no Painel. Agora vamos voltar à tela "
          "principal.",
          "ciclo de melhoria contínua do NIST CSF 2.0", acao="nist_aba:Painel"),
    Passo("Sobre o S-Cyber PM",
          "Por fim, a janela Sobre reúne a versão, os autores, os padrões de mercado "
          "utilizados, os componentes instalados e as instruções para gerar o executável de "
          "distribuição.",
          "padrões de mercado · PyInstaller", destaque="sobre", acao="sobre"),
    Passo("Até a próxima!",
          "Este foi o Tour do S-Cyber PM. Você pode repeti-lo quando quiser, em Arquivo, "
          "Tour. Obrigada pela atenção, e bons estudos!",
          "", destaque="tour"),
]


SO_PM = ("sei", "radio", "espiao")     # o mesmo que modLicenca.EXCLUSIVO_PM

BOAS_VINDAS_BUSINESS = (
    "Olá! Eu sou a narradora do Tour do S-Cyber Business, o diagnóstico de segurança "
    "cibernética para pequenas e médias empresas. Nos próximos minutos, vou abrir cada "
    "ferramenta e explicar, de forma simples, o que ela faz e como ajuda a proteger a sua "
    "empresa. Você pode pausar, voltar ou avançar a qualquer momento, nos botões desta janela.")


def _institucional(passo):
    """Passo de recurso exclusivo da modalidade S-Cyber PM (SEI, rádio e Espião didático)."""
    acao = passo.acao or ""
    return passo.destaque in SO_PM or acao in SO_PM or acao.endswith("Consultas SEI")


def _para_business(passo):
    """Mesmo passo com o nome do produto da Business e sem a apresentação institucional."""
    from dataclasses import replace
    if passo.titulo == "Boas-vindas":
        return replace(passo, texto=BOAS_VINDAS_BUSINESS)
    return replace(passo, titulo=passo.titulo.replace("S-Cyber PM", "S-Cyber"),
                   texto=passo.texto.replace("S-Cyber PM", "S-Cyber Business")
                   .replace("bons estudos", "bom trabalho"))


def roteiro(institucional=True):
    """Passos do Tour para a modalidade em uso."""
    if institucional:
        return list(ROTEIRO)
    return [_para_business(p) for p in ROTEIRO if not _institucional(p)]


# ==========================================================
# JANELA DO TOUR
# ==========================================================

class FormTour(tk.Toplevel):
    """Janela de controle do Tour: fica por cima, no canto inferior direito."""

    LARGURA, ALTURA = 470, 428

    def __init__(self, parent, ribbon=None, status=None, acoes=None, institucional=True):
        super().__init__(parent)
        # S-Cyber Business (institucional=False): sem os passos das integrações da PM (SEI).
        self.roteiro = roteiro(institucional)
        self.title(("S-Cyber PM" if institucional else "S-Cyber Business") + " - Tour")
        self.resizable(False, False)
        self.attributes("-topmost", True)            # os formulários abrem por baixo dela
        self.raiz = parent
        self.ribbon = ribbon
        self.status = status
        self.acoes = acoes or {}

        self.narradora = Narradora()
        self.indice = -1
        self.pausado = False
        self.auto = tk.BooleanVar(value=True)
        self.contorno = tk.BooleanVar(value=True)
        self.holofote = Destaque(parent, acima=[self])   # contorno vermelho + fundo P&B
        self.abertas = []                            # janelas abertas pelo passo atual
        self._inicio_fala = 0.0
        self._fim_estimado = 0.0
        self._agendado = None
        self._vigia = None

        self._criar_interface()
        self._posicionar()
        self.protocol("WM_DELETE_WINDOW", self.encerrar)
        self.bind("<Escape>", lambda e: self.encerrar())
        self.bind("<Right>", lambda e: self.proximo())
        self.bind("<Left>", lambda e: self.anterior())
        self.bind("<space>", lambda e: self.alternar_pausa())
        self.after(400, lambda: self.ir_para(0))

    # ------------------------------------------------------
    # Interface
    # ------------------------------------------------------

    def _criar_interface(self):
        topo = tk.Canvas(self, height=52, bg="#101010", highlightthickness=0, bd=0)
        topo.pack(fill="x")
        botao_fechar_cabecalho(self, self.encerrar, texto="■ Encerrar")
        self._icone = foto_icone("coruja", 40, self)
        topo.create_image(10, 26, image=self._icone, anchor="w")
        t1 = topo.create_text(58, 26, text="Tour do S-Cyber ", fill="white",
                              font=("Arial", 14, "bold"), anchor="w")
        topo.create_text(topo.bbox(t1)[2], 26, text="PM", fill="#ff0000",
                         font=("Arial", 14, "bold"), anchor="w")
        self._contador = topo.create_text(self.LARGURA - 112, 26, text="", fill="#bbbbbb",
                                          font=("Arial", 9), anchor="e")
        self._topo = topo

        corpo = ttk.Frame(self, padding=(12, 8, 12, 10))
        corpo.pack(fill="both", expand=True)

        self.titulo = ttk.Label(corpo, text="", font=("Segoe UI", 12, "bold"),
                                foreground="#b00000")
        self.titulo.pack(anchor="w")
        self.legenda = tk.Text(corpo, height=7, wrap="word", font=("Segoe UI", 10),
                               relief="flat", bg=self.cget("bg"), padx=0, pady=4,
                               cursor="arrow", takefocus=False)
        self.legenda.pack(fill="both", expand=True)
        self.legenda.configure(state="disabled")
        self.tecnologias = ttk.Label(corpo, text="", foreground="#1b5e9a", wraplength=440,
                                     justify="left", font=("Segoe UI", 9))
        self.tecnologias.pack(anchor="w", pady=(2, 6))

        self.progresso = ttk.Progressbar(corpo, maximum=len(self.roteiro), mode="determinate")
        self.progresso.pack(fill="x")

        botoes = ttk.Frame(corpo)
        botoes.pack(fill="x", pady=(8, 0))
        self.bt_anterior = ttk.Button(botoes, text="◀ Anterior", command=self.anterior)
        self.bt_anterior.pack(side="left")
        self.bt_pausa = ttk.Button(botoes, text="⏸ Pausar", width=12,
                                   command=self.alternar_pausa)
        self.bt_pausa.pack(side="left", padx=6)
        self.bt_proximo = ttk.Button(botoes, text="Próximo ▶", command=self.proximo)
        self.bt_proximo.pack(side="left")

        opcoes = ttk.Frame(corpo)
        opcoes.pack(fill="x", pady=(8, 0))
        ttk.Checkbutton(opcoes, text="Avançar sozinho", variable=self.auto).pack(side="left")
        ttk.Label(opcoes, text="Velocidade da voz:").pack(side="left", padx=(16, 4))
        escala = ttk.Scale(opcoes, from_=-5, to=5, orient="horizontal", length=110,
                           command=lambda v: self.narradora.velocidade(round(float(v))))
        escala.set(0)
        escala.pack(side="left")
        if not self.narradora.ativa:
            escala.state(["disabled"])
        ttk.Checkbutton(corpo, text="Contorno vermelho e fundo em preto e branco",
                        variable=self.contorno, command=self._alternar_contorno).pack(
            anchor="w", pady=(6, 0))

        voz = (f"Voz: {self.narradora.nome}" if self.narradora.ativa and not
               self.narradora.aviso else self.narradora.aviso)
        ttk.Label(corpo, text=voz, wraplength=440, justify="left", font=("Segoe UI", 8),
                  foreground="#9a6700" if self.narradora.aviso else "#606060").pack(
            anchor="w", pady=(6, 0))

    def _posicionar(self):
        """Canto inferior direito da tela, acima da barra de tarefas."""
        self.update_idletasks()
        x = self.winfo_screenwidth() - self.LARGURA - 24
        y = self.winfo_screenheight() - self.ALTURA - 80
        self.geometry(f"{self.LARGURA}x{self.ALTURA}+{max(0, x)}+{max(0, y)}")

    # ------------------------------------------------------
    # Passos
    # ------------------------------------------------------

    def ir_para(self, indice):
        if not self.winfo_exists() or not 0 <= indice < len(self.roteiro):
            return
        self._cancelar_agendado()
        self.narradora.calar()
        self._fechar_abertas()
        self.indice = indice
        passo = self.roteiro[indice]
        if not (passo.acao or "").startswith("nist"):
            voltar = self.acoes.get("nist_voltar")   # sai do painel NIST ao mudar de assunto
            if voltar is not None:
                voltar()

        self.titulo.configure(text=passo.titulo)
        self.legenda.configure(state="normal")
        self.legenda.delete("1.0", "end")
        self.legenda.insert("1.0", passo.texto)
        self.legenda.configure(state="disabled")
        self.tecnologias.configure(text=f"Tecnologias: {passo.tecnologias}"
                                   if passo.tecnologias else "")
        self.progresso["value"] = indice + 1
        self._topo.itemconfigure(self._contador, text=f"Passo {indice + 1} de {len(self.roteiro)}")
        self.bt_anterior.state(["disabled" if indice == 0 else "!disabled"])
        self.bt_proximo.state(["disabled" if indice == len(self.roteiro) - 1 else "!disabled"])
        if self.status is not None:
            self.status.mensagem(f"Tour: {passo.titulo}")

        if self.ribbon is not None and passo.destaque:
            self.ribbon.destacar(passo.destaque)
        self._acender(passo)
        if passo.acao:
            self.after(300, self._executar, passo.acao, indice)

        self.pausado = False
        self.bt_pausa.configure(text="⏸ Pausar")
        self.narradora.falar(passo.texto)
        self._inicio_fala = time.monotonic()
        self._fim_estimado = self._inicio_fala + len(passo.texto.split()) / PALAVRAS_POR_SEGUNDO
        self._vigiar()

    def _executar(self, acao, indice):
        if not self.winfo_exists() or indice != self.indice:
            return                                   # o usuário já mudou de passo
        if acao == "percorrer_ribbon":
            self._percorrer_ribbon()
            return
        chave, _, argumento = acao.partition(":")      # "nist_aba:Riscos" -> ("nist_aba", "Riscos")
        abrir = self.acoes.get(chave)
        if abrir is None:
            return
        if argumento:
            abrir = lambda f=abrir, a=argumento: f(a)
        antes = set(self._janelas())
        try:
            abrir()
        except Exception as e:  # noqa: BLE001 - um formulário com problema não para o Tour
            self.tecnologias.configure(
                text=f"(não foi possível abrir este formulário: {type(e).__name__}: {e})")
            return
        self.update_idletasks()
        for janela in self._janelas():
            if janela not in antes:
                self.abertas.append(janela)
                try:
                    janela.grab_release()            # janelas modais não podem travar o Tour
                except tk.TclError:
                    pass
        self.lift()
        if self.contorno.get() and self.abertas:
            # Passa o contorno do ícone para o formulário, depois que ele se desenhar
            self.holofote.destacar_janela(self.abertas[0], atraso_ms=900)

    def _percorrer_ribbon(self):
        """Mostra as abas da Ribbon uma por vez, enquanto a narradora fala."""
        if self.ribbon is None:
            return
        abas = list(getattr(self.ribbon, "_abas", {}))
        indice = self.indice
        for i, nome in enumerate(abas):
            self.after(2200 * (i + 1), self._mostrar_aba, nome, indice)

    def _mostrar_aba(self, nome, indice):
        if self.indice != indice or not self.winfo_exists():
            return
        # A Ribbon está dentro do buraco do holofote (ao vivo): a troca de aba
        # aparece sem precisar de uma nova foto da tela
        self.ribbon.selecionar(nome)

    # ------------------------------------------------------
    # Holofote (contorno vermelho, resto em preto e branco)
    # ------------------------------------------------------

    def _acender(self, passo):
        """Contorno inicial do passo: o botão da Ribbon (ou a Ribbon inteira); o
        formulário ganha o contorno depois que abre (em _executar)."""
        self.holofote.esconder()
        if not self.contorno.get() or self.ribbon is None:
            return
        if passo.acao == "percorrer_ribbon":
            self.holofote.destacar_widget(self.ribbon, atraso_ms=250)
        elif passo.destaque in self.ribbon.botoes:
            self.holofote.destacar_widget(self.ribbon.botoes[passo.destaque][1], atraso_ms=250)

    def _alternar_contorno(self):
        if not self.contorno.get():
            self.holofote.esconder()
        elif self.abertas:
            self.holofote.destacar_janela(self.abertas[0])
        elif 0 <= self.indice < len(self.roteiro):
            self._acender(self.roteiro[self.indice])

    def _janelas(self):
        # A película do holofote também é uma Toplevel da raiz: não conta como formulário
        return [w for w in self.raiz.winfo_children()
                if isinstance(w, tk.Toplevel) and w is not self
                and w is not self.holofote._janela and w.winfo_exists()]

    def _fechar_abertas(self):
        for janela in self.abertas:
            try:
                if not janela.winfo_exists():
                    continue
                fechar = getattr(janela, "_fechar", None)   # formulários com limpeza própria
                (fechar or janela.destroy)()
            except tk.TclError:
                pass
        self.abertas = []

    # ------------------------------------------------------
    # Avanço automático
    # ------------------------------------------------------

    def _vigiar(self):
        """Confere a cada 300 ms se a fala acabou, para avançar sozinho."""
        if self._vigia is not None:
            self.after_cancel(self._vigia)
        self._vigia = self.after(300, self._conferir_fim)

    def _conferir_fim(self):
        self._vigia = None
        if not self.winfo_exists():
            return
        if self.pausado or self._agendado is not None:
            self._vigiar()
            return
        if self.narradora.ativa:
            terminou = (time.monotonic() - self._inicio_fala > 0.8
                        and not self.narradora.falando())
        else:
            terminou = time.monotonic() >= self._fim_estimado
        if terminou:
            if self.auto.get() and self.indice < len(self.roteiro) - 1:
                self._agendado = self.after(PAUSA_ENTRE_PASSOS_MS, self._avancar_agendado)
            return                                   # parou de vigiar até o próximo passo
        self._vigiar()

    def _avancar_agendado(self):
        self._agendado = None
        self.proximo()

    def _cancelar_agendado(self):
        if self._agendado is not None:
            self.after_cancel(self._agendado)
            self._agendado = None

    # ------------------------------------------------------
    # Controles
    # ------------------------------------------------------

    def proximo(self):
        if self.indice < len(self.roteiro) - 1:
            self.ir_para(self.indice + 1)

    def anterior(self):
        if self.indice > 0:
            self.ir_para(self.indice - 1)

    def alternar_pausa(self):
        self.pausado = not self.pausado
        if self.pausado:
            self._cancelar_agendado()
            self.narradora.pausar()
            self._restante = max(0.0, self._fim_estimado - time.monotonic())
            self.bt_pausa.configure(text="▶ Continuar")
        else:
            self.narradora.continuar()
            self._fim_estimado = time.monotonic() + getattr(self, "_restante", 0.0)
            self.bt_pausa.configure(text="⏸ Pausar")
            self._vigiar()

    def encerrar(self):
        self._cancelar_agendado()
        if self._vigia is not None:
            self.after_cancel(self._vigia)
        self.narradora.calar()
        self.holofote.fechar()
        self._fechar_abertas()
        voltar = self.acoes.get("nist_voltar")
        if voltar is not None:
            voltar()
        if self.status is not None:
            self.status.mensagem()
        self.destroy()


# ==========================================================
# EXECUÇÃO DIRETA (teste: só a narração, sem abrir formulários)
# ==========================================================

def main():
    root = tk.Tk()
    root.withdraw()
    form = FormTour(root)
    form.bind("<Destroy>", lambda e: root.quit() if e.widget is form else None)
    root.mainloop()


if __name__ == "__main__":
    main()
