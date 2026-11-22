"""Criptografia em repouso dos campos de texto do banco NIST (AES-256-GCM).

A chave NÃO é guardada em lugar nenhum: deriva (HKDF-SHA256) da chave que o
S-Cyber PM obtém assinando um rótulo com a chave privada do certificado
autorizado (formOpcoes). Sem o certificado e sua chave privada, os textos
do banco não podem ser lidos.

Formato de cada campo cifrado:  enc1:<base64(nonce de 12 bytes + texto cifrado + tag)>
Números, datas, situações e hashes continuam em claro: são usados em filtros,
prazos e ordenação e não identificam pessoas ou casos.
"""
from __future__ import annotations

import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PREFIX = 'enc1:'
AAD = b'scyber-nist-intelligence-db-v1'
KEY_CHECK = 'scyber-nist-key-check'
LOCKED = '[cifrado]'


def derive_key(master_key: bytes) -> bytes:
    """Subchave própria do módulo: nunca reutiliza a chave das Opções diretamente."""
    if not isinstance(master_key, (bytes, bytearray)) or len(master_key) < 32:
        raise ValueError('Chave do certificado indisponível ou inválida.')
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b'S-Cyber NIST Intelligence',
                info=b'scyber-nist-db-aes256gcm').derive(bytes(master_key))


class FieldCipher:
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError('A chave deve ter 32 bytes.')
        self._aes = AESGCM(key)

    def encrypt(self, value):
        if not isinstance(value, str) or value == '' or value.startswith(PREFIX):
            return value
        nonce = os.urandom(12)
        data = self._aes.encrypt(nonce, value.encode('utf-8'), AAD)
        return PREFIX + base64.b64encode(nonce + data).decode('ascii')

    def decrypt(self, value):
        if not is_encrypted(value):
            return value
        raw = base64.b64decode(value[len(PREFIX):])
        return self._aes.decrypt(raw[:12], raw[12:], AAD).decode('utf-8')

    def check_token(self):
        return self.encrypt(KEY_CHECK)

    def matches(self, token):
        try:
            return self.decrypt(token) == KEY_CHECK
        except (InvalidTag, ValueError):
            return False


def is_encrypted(value):
    return isinstance(value, str) and value.startswith(PREFIX)
