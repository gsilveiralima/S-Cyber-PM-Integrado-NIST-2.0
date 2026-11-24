"""S-Cyber 2.0, Fase 5: segurança em nuvem (Azure, somente leitura) no fluxo do Diagnóstico Inteligente."""
import ast
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))

from nist_intelligence import achados as A  # noqa: E402
from nist_intelligence import core, crypto, fontes  # noqa: E402
from nist_intelligence import diagnostico as D  # noqa: E402
from nist_intelligence import nuvem as N  # noqa: E402

KEY = crypto.derive_key(os.urandom(32))
CONTA = {'id': '11111111-2222-3333-4444-555555555555', 'name': 'Assinatura de teste', 'tenantId': 't',
         'user': 'leitor@exemplo.example'}


def corrigido():
    raw = N.ambiente_simulado()
    for c in raw['storage']:
        c['properties'].update(allowBlobPublicAccess=False, minimumTlsVersion='TLS1_2',
                               networkAcls={'defaultAction': 'Deny'})
    raw['nsg'][0]['properties']['securityRules'] = [N._regra('permitir-https', '443')]
    raw['vaults'] = [{'name': 'rsv-demo'}]
    return raw


class AvaliacaoTests(unittest.TestCase):
    def test_ambiente_simulado_mostra_os_problemas(self):
        r = {x['id']: x for x in N.evaluate(N.ambiente_simulado())}
        self.assertEqual(set(r), {'az_storage_public', 'az_storage_crypto', 'az_nsg', 'az_owners', 'az_backup',
                                  'az_logging'})
        self.assertEqual(r['az_storage_public']['status'], 'Falha')
        self.assertIn('stdemodocumentos', r['az_storage_public']['detail'])
        self.assertEqual(r['az_storage_crypto']['status'], 'Atenção')         # TLS 1.0
        self.assertEqual(r['az_nsg']['status'], 'Falha')
        self.assertIn('3389 (RDP)', r['az_nsg']['detail'])
        self.assertNotIn('443', r['az_nsg']['detail'])                         # HTTPS aberto é esperado
        self.assertEqual(r['az_owners']['status'], 'Atenção')                  # 4 proprietários
        self.assertEqual(r['az_backup']['status'], 'Falha')                    # VM sem cofre
        self.assertEqual(r['az_logging']['status'], 'Atenção')
        for x in r.values():
            self.assertTrue(x['subs'] and all(s in core.SUB_CODES for s in x['subs']), x['id'])

    def test_faixas_de_porta_e_origens(self):
        aberta = N._regra('faixa', '3000-3400', 'Internet')
        self.assertTrue(N._aberta_a_internet(aberta))
        self.assertEqual(N._portas(aberta), ['3306 (MySQL)', '3389 (RDP)'])
        self.assertFalse(N._aberta_a_internet(N._regra('interna', '22', '10.0.0.0/8')))
        self.assertEqual(N._portas(N._regra('tudo', '*')), ['todas as portas'])

    def test_assinatura_sem_armazenamento_nao_afirma_https(self):
        """Validação real (Azure for Students, 24/11): sem contas, o texto dizia 'Só HTTPS e TLS 1.2'."""
        r = {x['id']: x for x in N.evaluate({'meta': {}, 'storage': [], 'nsg': [], 'roles': [], 'vaults': [],
                                               'vms': [], 'diag': []})}
        self.assertNotIn('HTTPS', r['az_storage_crypto']['detail'])
        self.assertIn('nada a verificar', r['az_storage_crypto']['detail'])

    def test_falha_de_consulta_nunca_aprova(self):
        raw = {'meta': {'host': 'x'}, 'storage': {'erro': 'Acesso recusado (HTTP 403)'}, 'nsg': None,
               'roles': {'erro': 'x'}, 'vaults': {'erro': 'x'}, 'vms': [], 'diag': {'erro': 'x'}}
        self.assertEqual({x['status'] for x in N.evaluate(raw)}, {'Indisponível'})

    def test_toda_verificacao_tem_recomendacao(self):
        for x in N.evaluate(N.ambiente_simulado()):
            rec = D.recomendacao(x['id'])
            self.assertIsNot(rec, D.SEM_REGRA, x['id'])


class ColetaTests(unittest.TestCase):
    """GETs no formato da API do Azure Resource Manager (lista com 'value' e 'nextLink')."""

    def test_so_get_com_token_paginacao_e_falhas_separadas(self):
        chamadas = []
        pagina2 = 'https://management.azure.com/next?page=2'

        def http(url, headers=None, timeout=20):
            chamadas.append((url, headers))
            if url == pagina2:
                return 200, json.dumps({'value': [{'name': 'st2', 'properties': {}}]}).encode()
            if 'Microsoft.Storage' in url:
                return 200, json.dumps({'value': [{'name': 'st1', 'properties': {}}], 'nextLink': pagina2}).encode()
            if 'roleAssignments' in url:
                raise fontes.FalhaFonte(fontes.ACESSO_RECUSADO, 'Acesso recusado (HTTP 403)')
            return 200, b'{"value": []}'

        raw = N.coletar_azure(CONTA, token='TOKEN-DE-TESTE', http=http)
        self.assertEqual([c['name'] for c in raw['storage']], ['st1', 'st2'])
        self.assertIn('403', raw['roles']['erro'])
        self.assertEqual(raw['meta']['host'], CONTA['id'])
        self.assertFalse(raw['meta']['simulado'])
        for url, headers in chamadas:
            self.assertTrue(url.startswith('https://management.azure.com/'))
            self.assertEqual(headers['Authorization'], 'Bearer TOKEN-DE-TESTE')
        self.assertNotIn('TOKEN-DE-TESTE', json.dumps(raw))                   # o token não vai para a evidência

    def test_sem_azure_cli_explica_o_que_fazer(self):
        with mock.patch.object(N.shutil, 'which', return_value=None):
            with self.assertRaisesRegex(N.ErroNuvem, 'az login'):
                N.conta_azure()

    def test_cli_so_le(self):
        """O CLI só é chamado com 'account show' e 'account get-access-token'."""
        fonte = (BASE / 'nist_intelligence' / 'nuvem.py').read_text(encoding='utf-8')
        chamadas = [ast.literal_eval(ast.unparse(n.args[0])) for n in ast.walk(ast.parse(fonte))
                    if isinstance(n, ast.Call) and getattr(n.func, 'id', '') == '_az']
        self.assertEqual(sorted(chamadas), ['account', 'account'])
        self.assertIn("'show'", fonte)
        self.assertIn("'get-access-token'", fonte)
        for proibido in ('requests.put', 'requests.post', 'method=', "'create'", "'delete'", "'update'"):
            self.assertNotIn(proibido, fonte)

    def test_erro_do_cli(self):
        falhou = subprocess.CompletedProcess([], 1, '', 'ERROR: Please run "az login" to setup account.')
        with mock.patch.object(N.shutil, 'which', return_value='az'), \
                mock.patch.object(N.subprocess, 'run', return_value=falhou):
            with self.assertRaisesRegex(N.ErroNuvem, 'az login'):
                N.conta_azure()


class FluxoNuvemTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = core.connect(Path(self.tmp.name) / 'n.db', KEY)
        self.db.definir_sessao('ana (PC)', 'usuario')
        self.ev = Path(self.tmp.name) / 'ev'

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_mesmo_fluxo_do_diagnostico_e_melhoria_comprovada(self):
        r = D.registrar(self.db, N.ambiente_simulado(), self.ev, nuvem=True)
        self.assertTrue(r['simulado'] and r['nuvem'])
        self.assertEqual(r['ativo']['kind'], 'Nuvem (assinatura)')
        self.assertIn('[SIMULADO]', r['ativo']['name'])
        origem = self.db.execute('SELECT source FROM collections WHERE id=?', (r['coleta_id'],)).fetchone()[0]
        self.assertEqual(origem, 'Nuvem (simulada)')
        por_id = {i['id']: i for i in r['itens']}
        self.assertTrue(por_id['az_nsg']['achado_id'])
        self.assertEqual(por_id['az_nsg']['prioridade'], 'Alta')               # Falha 3 + Média 1 + exposição 1
        self.assertIn('Bastion', por_id['az_nsg']['recomendacao']['corrigir'])
        r2 = D.registrar(self.db, corrigido(), self.ev, nuvem=True)
        tend = {c: t for c, _, _, _, t in r2['comparacao']}
        for check in ('az_storage_public', 'az_storage_crypto', 'az_nsg', 'az_backup'):
            self.assertEqual(tend[check], 'Melhorou', check)
        self.assertEqual(r2['ativo']['id'], r['ativo']['id'])
        # Nuvem e computador ficam em ativos separados e não se misturam na comparação
        self.assertIsNone(D.ultimo(self.db))                                  # 'ultimo' é o do computador
        self.assertEqual(len(A.assets(self.db)), 1)


if __name__ == '__main__':
    unittest.main()
