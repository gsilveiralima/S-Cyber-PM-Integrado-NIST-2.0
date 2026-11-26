"""Verificação, em Python, da assinatura destacada CMS/PKCS #7 (RFC 5652) feita pelo
Windows com o certificado do usuário (formSign.assinar_bytes, SignedCms do .NET).

Quem ASSINA é sempre o Windows: a chave privada não sai do repositório de
certificados e pode ser não exportável. Aqui só se CONFERE a assinatura, com a
chave pública que vem dentro do próprio CMS, sem depender do PowerShell — por
isso funciona (e é testável) em qualquer sistema.

Aceita o que o S-Cyber PM produz: SignedData com um signatário, SHA-256 e
atributos assinados (messageDigest obrigatório), chave RSA (PKCS #1 v1.5) ou ECDSA.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

OID_SIGNED_DATA = '1.2.840.113549.1.7.2'
OID_DATA = '1.2.840.113549.1.7.1'
OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4'
OID_SIGNING_TIME = '1.2.840.113549.1.9.5'
OID_CONTENT_TYPE = '1.2.840.113549.1.9.3'
DIGESTS = {'2.16.840.1.101.3.4.2.1': (hashes.SHA256, hashlib.sha256),
           '2.16.840.1.101.3.4.2.2': (hashes.SHA384, hashlib.sha384),
           '2.16.840.1.101.3.4.2.3': (hashes.SHA512, hashlib.sha512)}


class SignatureError(ValueError):
    pass


# ------------------------------------------------------------------ DER mínimo
def _tlv(data, pos=0):
    """(tag, início do conteúdo, fim) do elemento DER em data[pos:]."""
    if pos + 2 > len(data):
        raise SignatureError('Assinatura truncada.')
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or pos + n > len(data):
            raise SignatureError('Comprimento DER inválido.')
        length = int.from_bytes(data[pos:pos + n], 'big')
        pos += n
    end = pos + length
    if end > len(data):
        raise SignatureError('Assinatura truncada.')
    return tag, pos, end


def _children(data, start, end):
    out = []
    while start < end:
        tag, s, e = _tlv(data, start)
        out.append((tag, start, s, e))     # tag, início do TLV, início do conteúdo, fim
        start = e
    return out


def _oid(raw):
    first = raw[0]
    parts = [first // 40 if first < 80 else 2, first % 40 if first < 80 else first - 80]
    value = 0
    for b in raw[1:]:
        value = (value << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(value)
            value = 0
    return '.'.join(map(str, parts))


def _expect(node, tag, what):
    if node[0] != tag:
        raise SignatureError(f'Estrutura CMS inválida ({what}).')
    return node


def _time(data, node):
    tag, _, s, e = node
    text = data[s:e].decode('ascii')
    fmt = '%y%m%d%H%M%SZ' if tag == 0x17 else '%Y%m%d%H%M%SZ'
    return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)


def thumbprint(cert):
    """Impressão digital como o Windows mostra (SHA-1 do certificado, maiúsculas)."""
    from cryptography.hazmat.primitives.serialization import Encoding
    return hashlib.sha1(cert.public_bytes(Encoding.DER)).hexdigest().upper()   # noqa: S324 — é o thumbprint


def _subject(cert):
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return cn[0].value if cn else cert.subject.rfc4514_string()


def verify_detached(content: bytes, cms_der: bytes):
    """Confere a assinatura destacada `cms_der` sobre `content`.

    Devolve {thumb, subject, not_before, not_after, signing_time}; levanta SignatureError se a
    assinatura não confere ou a estrutura não é a esperada."""
    try:
        return _verify(bytes(content), bytes(cms_der))
    except SignatureError:
        raise
    except (IndexError, ValueError, UnicodeDecodeError, TypeError) as exc:
        raise SignatureError(f'Assinatura ilegível: {exc}') from exc


def _verify(content, data):
    tag, s, e = _tlv(data)
    if tag != 0x30 or e != len(data):
        raise SignatureError('Não é uma assinatura CMS.')
    top = _children(data, s, e)
    if len(top) < 2 or _oid(data[top[0][2]:top[0][3]]) != OID_SIGNED_DATA or top[1][0] != 0xA0:
        raise SignatureError('A assinatura não é do tipo SignedData.')
    _, sd_s, sd_e = _tlv(data, top[1][2])
    sd = _children(data, sd_s, sd_e)
    # version, digestAlgorithms, encapContentInfo, [0] certificates, [1] crls, signerInfos
    certs, signer_set = [], None
    encap = _expect(sd[2], 0x30, 'conteúdo')
    encap_items = _children(data, encap[2], encap[3])
    if _oid(data[encap_items[0][2]:encap_items[0][3]]) != OID_DATA or len(encap_items) > 1:
        raise SignatureError('A assinatura não é destacada.')
    for node in sd[3:]:
        if node[0] == 0xA0:
            for c in _children(data, node[2], node[3]):
                if c[0] == 0x30:
                    certs.append(x509.load_der_x509_certificate(data[c[1]:c[3]]))
        elif node[0] == 0x31:
            signer_set = node
    if signer_set is None or not certs:
        raise SignatureError('A assinatura não traz o signatário e o certificado.')
    signers = _children(data, signer_set[2], signer_set[3])
    if len(signers) != 1:
        raise SignatureError('Esperado exatamente um signatário.')
    si = _children(data, signers[0][2], signers[0][3])
    # version, sid, digestAlgorithm, [0] signedAttrs, signatureAlgorithm, signature
    sid = si[1]
    alg = _children(data, si[2][2], si[2][3])[0]
    digest_alg = _oid(data[alg[2]:alg[3]])
    if digest_alg not in DIGESTS:
        raise SignatureError('Algoritmo de resumo não aceito (use SHA-256).')
    hash_cls, hashlib_fn = DIGESTS[digest_alg]
    attrs = _expect(si[3], 0xA0, 'atributos assinados')
    signature = _expect(si[5], 0x04, 'assinatura')
    message_digest, signing_time, content_type = None, None, None
    for a in _children(data, attrs[2], attrs[3]):
        oid_node, values = _children(data, a[2], a[3])
        oid = _oid(data[oid_node[2]:oid_node[3]])
        first = _children(data, values[2], values[3])[0]
        if oid == OID_MESSAGE_DIGEST:
            message_digest = data[first[2]:first[3]]
        elif oid == OID_SIGNING_TIME:
            signing_time = _time(data, first)
        elif oid == OID_CONTENT_TYPE:
            content_type = _oid(data[first[2]:first[3]])
    if message_digest is None or content_type not in (None, OID_DATA):
        raise SignatureError('A assinatura não traz o resumo do conteúdo.')
    if message_digest != hashlib_fn(bytes(content)).digest():
        raise SignatureError('O conteúdo foi alterado depois de assinado.')

    # Signatário: IssuerAndSerialNumber (o padrão do SignedCms) ou SubjectKeyIdentifier.
    cert = None
    if sid[0] == 0x30:
        serial_node = _children(data, sid[2], sid[3])[1]
        serial = int.from_bytes(data[serial_node[2]:serial_node[3]], 'big', signed=True)
        cert = next((c for c in certs if c.serial_number == serial), None)
    elif sid[0] == 0x80:
        ski = data[sid[2]:sid[3]]
        for c in certs:
            try:
                if c.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest == ski:
                    cert = c
            except x509.ExtensionNotFound:
                pass
    if cert is None:
        raise SignatureError('O certificado do signatário não está na assinatura.')
    signed = b'\x31' + data[attrs[1] + 1:attrs[3]]        # [0] IMPLICIT -> SET OF (RFC 5652, 5.4)
    key = cert.public_key()
    try:
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(data[signature[2]:signature[3]], signed, padding.PKCS1v15(), hash_cls())
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(data[signature[2]:signature[3]], signed, ec.ECDSA(hash_cls()))
        else:
            raise SignatureError('Tipo de chave não aceito.')
    except InvalidSignature as exc:
        raise SignatureError('A assinatura não confere com o certificado.') from exc
    return {'thumb': thumbprint(cert), 'subject': _subject(cert),
            'not_before': cert.not_valid_before_utc.date().isoformat(),
            'not_after': cert.not_valid_after_utc.date().isoformat(),
            'signing_time': signing_time.isoformat() if signing_time else ''}


def windows_signer(thumb):
    """Função de assinatura com o certificado do usuário (Windows, chave não exportável)."""
    def sign(data: bytes) -> bytes:
        from formSign import assinar_bytes
        return assinar_bytes(data, thumb)
    return sign
