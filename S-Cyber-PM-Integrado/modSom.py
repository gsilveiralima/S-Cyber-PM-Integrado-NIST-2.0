# ==============================================================================
#  S-Cyber PM - Cryptography and Digital Certificate Framework
# ------------------------------------------------------------------------------
#  Arquivo     : modSom.py
#  Descrição   : Tocador de música dentro do aplicativo (MP3/WAV pelo MCI do
#                Windows), sem programas externos
#  Tipo        : Módulo de apoio
#  Versão      : ver formAbout.APP_VERSAO (fonte única da versão)
#  Revisão     : 2026-11-16
#  Autores     : MAJ Daniel Medrado - PMGO
#                MAJ Leonidio Alves de Moraes Junior - PMGO
#                SGT Gabriel Silvieira Lima - PMGO
#  Instituição : Polícia Militar do Estado de Goiás
#  Contato     : leonidio.moraes@goias.gov.br
#  Licença     : Uso interno da instituição. Proibida a redistribuição sem
#                autorização.
#  Requisitos  : Python 3.11+ (64 bits), Windows 10/11
#  Codificação : UTF-8
# ------------------------------------------------------------------------------
#  Histórico de revisões
#    Versão  Data        Alteração
#    1.4     2026-11-15  Criação
#            2026-11-16  MP3 com capa embutida (ID3v2): toca por uma cópia sem a etiqueta,
#                          pois o MCI recusava o arquivo original
# ==============================================================================
"""
S-Cyber PM - tocador de música dentro do próprio aplicativo.

Usa o MCI (Media Control Interface, winmm.dll) do Windows: o som é tocado pelo
próprio processo do S-Cyber PM, sem abrir o Media Player nem outro programa, e
sem nenhum módulo a instalar. O MP3 vai embutido no .exe (gerarExe.py).

    musica = Musica("Surveillance Pulse.mp3")   # procura junto do aplicativo
    musica.tocar(repetir=True)                  # em loop, sem travar a interface
    musica.parar()

Se o arquivo não existir ou o Windows não conseguir tocá-lo, os métodos não
fazem nada (o motivo fica em .erro): a música nunca impede o aplicativo de rodar.
"""

import ctypes
import itertools
import os
import tempfile

from modRecursos import localizar_recurso

VOLUME_PADRAO = 700                     # 0 a 1000
_numeros = itertools.count(1)


def _mci(comando):
    """Envia um comando ao MCI. Devolve (ok, resposta ou mensagem de erro)."""
    winmm = ctypes.windll.winmm
    resposta = ctypes.create_unicode_buffer(256)
    erro = winmm.mciSendStringW(comando, resposta, 255, None)
    if erro:
        mensagem = ctypes.create_unicode_buffer(256)
        winmm.mciGetErrorStringW(erro, mensagem, 255)
        return False, mensagem.value or f"erro MCI {erro}"
    return True, resposta.value


def _copia_sem_id3(caminho):
    """Copia o MP3 para a pasta temporária do Windows SEM a etiqueta ID3v2 do início.
    O MCI (DirectShow) recusa MP3 cuja etiqueta traz a capa do álbum embutida, com
    "Problema ao inicializar o MCI"; sem a etiqueta, o mesmo áudio toca.
    Devolve o caminho da cópia, ou None se o arquivo não tiver etiqueta ou não der."""
    try:
        with open(caminho, "rb") as f:
            dados = f.read()
        if dados[:3] != b"ID3" or len(dados) < 10:
            return None
        tamanho = (dados[6] << 21) | (dados[7] << 14) | (dados[8] << 7) | dados[9]
        inicio = 10 + tamanho + (10 if dados[5] & 0x10 else 0)       # 0x10: tem rodapé
        fd, copia = tempfile.mkstemp(prefix="scyber_musica_", suffix=".mp3")
        with os.fdopen(fd, "wb") as f:
            f.write(dados[inicio:])
        return copia
    except OSError:
        return None


class Musica:
    """Uma música aberta no MCI. Chame os métodos na thread da interface."""

    def __init__(self, nome_arquivo, volume=VOLUME_PADRAO):
        self.caminho = localizar_recurso(nome_arquivo)
        self.volume = volume
        self.erro = None
        self._alias = f"scyber_musica_{next(_numeros)}"
        self._aberta = False
        self._copia = None                  # cópia sem ID3, quando o MCI recusa o original
        if self.caminho is None:
            self.erro = f"{nome_arquivo} não encontrado junto do aplicativo"

    def _abrir(self):
        if self._aberta or self.caminho is None:
            return self._aberta
        tipo = "mpegvideo" if self.caminho.suffix.lower() == ".mp3" else "waveaudio"
        ok, msg = _mci(f'open "{self.caminho}" type {tipo} alias {self._alias}')
        if not ok and tipo == "mpegvideo":
            self._copia = _copia_sem_id3(self.caminho)
            if self._copia:
                ok, msg = _mci(f'open "{self._copia}" type {tipo} alias {self._alias}')
        if not ok:
            self.erro = msg
            self._apagar_copia()
            return False
        self.erro = None
        self._aberta = True
        if tipo == "mpegvideo":
            _mci(f"setaudio {self._alias} volume to {max(0, min(1000, int(self.volume)))}")
        return True

    def tocar(self, repetir=True):
        """Começa do início (em loop, se repetir). Não espera a música acabar."""
        if not self._abrir():
            return False
        _mci(f"seek {self._alias} to start")
        ok, msg = _mci(f"play {self._alias}" + (" repeat" if repetir else ""))
        if not ok:
            self.erro = msg
        return ok

    def tocando(self):
        return self._aberta and _mci(f"status {self._alias} mode")[1] == "playing"

    def parar(self):
        """Para e libera o arquivo. Pode ser chamada mais de uma vez."""
        if self._aberta:
            _mci(f"stop {self._alias}")
            _mci(f"close {self._alias}")
            self._aberta = False
        self._apagar_copia()

    def _apagar_copia(self):
        if self._copia:
            try:
                os.remove(self._copia)
            except OSError:
                pass                        # ainda em uso: fica para a limpeza do Windows
            self._copia = None
