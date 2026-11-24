"""Testes da preparação para produção: troca obrigatória da senha de fábrica,
política de senha e aceitação de certificados (lista e AC institucional).

Rodam em qualquer sistema: a interface (tkinter) e o PowerShell são substituídos.
"""
import base64
import datetime
import hashlib
import importlib
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

_STUBS = {name: mock.MagicMock() for name in (
    'tkinter', 'tkinter.messagebox', 'tkinter.ttk', 'modHello', 'modRecursos', 'modAssistente',
    'formAbout', 'formLogin', 'formSign', 'formListCerts', 'modRibbon', 'PIL')}


# A senha de fábrica das versões até 1.6 (pública no histórico do repositório): só os
# testes a conhecem, para provar que arquivos antigos ainda são obrigados a trocar.
SENHA_ANTIGA = 'not#_12345_senhorAgenteC'


class SenhaTests(unittest.TestCase):
    def setUp(self):
        self._patch = mock.patch.dict(sys.modules, _STUBS)
        self._patch.start()
        sys.modules.pop('formOpcoes', None)
        self.F = importlib.import_module('formOpcoes')
        self.gravado = {}
        self.F._gravar = lambda chave, thumb, dados: self.gravado.update(dados)
        self.F._estado.update(thumb='X', chave=b'k' * 32, dados=self.F._padrao())

    def tearDown(self):
        sys.modules.pop('formOpcoes', None)
        self._patch.stop()

    def test_politica(self):
        P = self.F.problema_senha
        self.assertIsNotNone(P('Ab1!x'))
        self.assertIsNotNone(P(SENHA_ANTIGA))
        self.assertIsNotNone(P('abcdefghijklmn'))
        self.assertIsNotNone(P('Agente#2026xyz', 'agente'))
        self.assertIsNotNone(P('Aa1!Aa1!Aa1!Aa1!'))
        self.assertIsNone(P('Corujinha#Goias2026'))

    def test_sem_senha_de_fabrica(self):
        F = self.F
        fonte = (Path(__file__).resolve().parents[1] / 'formOpcoes.py').read_text(encoding='utf-8')
        self.assertNotIn(SENHA_ANTIGA, fonte)                    # nenhuma senha no código
        self.assertFalse(F.senhas_criadas())                     # perfil novo: senhas a criar
        self.assertFalse(F.conferir_login('agente', ''))
        self.assertFalse(F.conferir_login('agente', SENHA_ANTIGA))

    def test_primeiro_acesso_obriga_troca(self):
        F = self.F
        self.assertTrue(F.precisa_trocar_senha(SENHA_ANTIGA))
        with self.assertRaises(F.ErroOpcoes):
            F.definir_senhas_iniciais('fraca', 'Relatorio$Pdf2026x')
        F.definir_senhas_iniciais('Corujinha#Goias2026', 'Relatorio$Pdf2026x')
        self.assertFalse(F.precisa_trocar_senha('Corujinha#Goias2026'))
        self.assertTrue(F.conferir_login('agente', 'Corujinha#Goias2026'))
        self.assertFalse(F.conferir_login('agente', SENHA_ANTIGA))
        self.assertTrue(F.senhas_criadas())
        self.assertEqual(self.gravado['senha_pdf'], 'Relatorio$Pdf2026x')
        self.assertIs(self.gravado['trocar_senha'], False)

    def test_arquivo_antigo_com_senha_de_fabrica(self):
        F = self.F
        # arquivo de versão antiga, sem a marca, com as senhas de fábrica gravadas
        F._estado['dados'] = {'usuario': 'agente', 'senha_acesso': F._hash_senha(SENHA_ANTIGA),
                              'senha_pdf': SENHA_ANTIGA}
        self.assertTrue(F.precisa_trocar_senha())
        self.assertTrue(F.conferir_login('agente', SENHA_ANTIGA))
        self.assertTrue(F.precisa_trocar_senha(SENHA_ANTIGA))

    def test_troca_pelas_opcoes(self):
        F = self.F
        F.salvar(senha_acesso_nova='Corujinha#Goias2026')
        self.assertTrue(F._estado['dados']['trocar_senha'])      # PDF ainda não criada
        F.salvar(senha_pdf_nova='Relatorio$Pdf2026x')
        self.assertFalse(F._estado['dados']['trocar_senha'])

    def test_chave_do_arquivo_publica(self):
        F = self.F
        self.assertEqual(F.chave_do_arquivo(), b'k' * 32)
        F._estado['dados'] = None
        self.assertIsNone(F.chave_do_arquivo())


class CertificadoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        src = (BASE / 'appSCyberPM.py').read_text(encoding='utf-8')
        head = src[:src.index('# ==========================================================\n# SPLASH SCREEN')]
        stubs = dict(_STUBS, formOpcoes=mock.MagicMock())
        with mock.patch.dict(sys.modules, stubs):
            cls.app = {'__name__': 'app_teste', '__file__': str(BASE / 'appSCyberPM.py')}
            exec(compile(head, 'appSCyberPM.py', 'exec'), cls.app)
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        nome = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'SGT Teste'),
                          x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Policia Militar do Estado de Goias')])
        agora = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(nome).issuer_name(nome)
                .public_key(cls.key.public_key()).serial_number(1)
                .not_valid_before(agora - datetime.timedelta(days=1))
                .not_valid_after(agora + datetime.timedelta(days=30)).sign(cls.key, hashes.SHA256()))
        cls.der = cert.public_bytes(serialization.Encoding.DER)
        cls.tp = hashlib.sha1(cls.der).hexdigest().upper()

    def _resp(self, via, cadeia, nonce):
        sig = self.key.sign(nonce, padding.PKCS1v15(), hashes.SHA256())
        return {'cert': base64.b64encode(self.der).decode(), 'sig': base64.b64encode(sig).decode(),
                'via': via, 'cadeia': cadeia}

    def test_lista_de_autorizados(self):
        V, n = self.app['verificar_resposta'], os.urandom(32)
        r = V(self._resp('lista', False, n), n, ['A' * 40, self.tp], False)
        self.assertTrue(r.ok)
        self.assertEqual(r.thumb, self.tp)
        self.assertFalse(V(self._resp('lista', False, n), n, ['A' * 40], False).ok)
        self.assertFalse(V(self._resp('lista', False, n), n, [self.tp], True).ok)   # exige cadeia
        self.assertTrue(V(self._resp('lista', False, n), n, self.tp, False).ok)     # compatível (str)

    def test_aceite_por_ac_exige_cadeia_e_titular(self):
        V, n = self.app['verificar_resposta'], os.urandom(32)
        self.assertFalse(V(self._resp('ac', False, n), n, [], False).ok)
        self.assertTrue(V(self._resp('ac', True, n), n, [], False, 'O=Policia Militar').ok)
        self.assertFalse(V(self._resp('ac', True, n), n, [], False, 'O=Outra Organizacao').ok)

    def test_assinatura_do_desafio(self):
        V = self.app['verificar_resposta']
        self.assertFalse(V(self._resp('lista', False, os.urandom(32)), os.urandom(32), [self.tp], False).ok)

    def test_script_so_com_hexadecimais(self):
        script = self.app['_script_assinatura'](['A' * 40], 'QUJD', False, ['C' * 40])
        self.assertIn("$permitidos = @('" + 'A' * 40 + "')", script)
        self.assertIn("$acs = @('" + 'C' * 40 + "')", script)
        self.assertEqual(self.app['_lista_normalizada'](["ab cd'; rm", 'C' * 40, 'c' * 40]), ['C' * 40])


if __name__ == '__main__':
    unittest.main()
