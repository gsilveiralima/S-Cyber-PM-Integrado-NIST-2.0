"""Gera a narração (pt-BR, voz Piper faber-medium) de cada parte do roteiro em FLAC."""
import json
import subprocess
import wave
from pathlib import Path

from piper import PiperVoice

MODELO = 'voz/pt_BR-faber-medium.onnx'
ESCALA = 0.97          # ritmo da fala (menor = mais rápido)
saida = Path('saida')
saida.mkdir(exist_ok=True)
voz = PiperVoice.load(MODELO)
duracoes = {}
for seg in json.load(open('segmentos.json', encoding='utf-8')):
    for i, parte in enumerate(seg['partes']):
        nome = f"{seg['id']}_{i}"
        wav = saida / f'{nome}.wav'
        with wave.open(str(wav), 'wb') as w:
            if hasattr(voz, 'synthesize_wav'):                       # piper-tts 1.3+
                from piper import SynthesisConfig
                voz.synthesize_wav(parte['fala'], w, syn_config=SynthesisConfig(length_scale=ESCALA))
            else:                                                     # piper-tts 1.2
                voz.synthesize(parte['fala'], w, length_scale=ESCALA, sentence_silence=0.25)
        with wave.open(str(wav)) as w:
            duracoes[nome] = w.getnframes() / w.getframerate()
        subprocess.run(['ffmpeg', '-v', 'error', '-y', '-i', str(wav), str(saida / f'{nome}.flac')], check=True)
        wav.unlink()
        print(nome, round(duracoes[nome], 2))
json.dump(duracoes, open(saida / 'duracoes.json', 'w'), indent=1)
