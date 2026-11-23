"""Testes da v1.2: feriados no prazo ANPD, coletas de vários computadores, coletor avulso,
evidência por subcategoria, pacote de consolidação assinado, cópia automática, retenção
e avisos de abertura."""
import datetime as dt
import json
import os
import sys
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.hazmat.primitives.serialization import pkcs7  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from nist_intelligence import collector, core, crypto, notificacoes, package, report, signing  # noqa: E402

APP_DIR = Path(__file__).resolve().parents[1]
KEY = crypto.derive_key(os.urandom(32))
SENHA = 'Pacote-Unidade-2026'


def _certificado(cn='S-Cyber-PM-NIST-2.0'):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=365)).sign(key, hashes.SHA256()))
    return cert, key


def _assinador(cert, key):
    """Faz o papel do Windows (formSign.assinar_bytes): CMS destacado com SHA-256."""
    def sign(data):
        return (pkcs7.PKCS7SignatureBuilder().set_data(data).add_signer(cert, key, hashes.SHA256())
                .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.DetachedSignature]))
    return sign


def _resultados(host_status):
    return [{'id': 'firewall', 'title': 'Firewall', 'status': host_status, 'detail': 'x', 'subs': ['PR.IR-01']}]


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.db = core.connect(self.dir / 'nist.db', KEY)
        self.db.actor = 'teste'

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()


class FeriadosTests(Base):
    def test_pascoa_e_feriados_nacionais(self):
        self.assertEqual(core.easter(2026), date(2026, 4, 5))
        self.assertEqual(core.easter(2027), date(2027, 3, 28))
        f = core.national_holidays(2026)
        self.assertIn(date(2026, 4, 3), f)                 # Paixão de Cristo
        self.assertIn(date(2026, 11, 20), f)               # Lei 14.759/2023
        self.assertNotIn(date(2026, 2, 17), f)             # Carnaval: ponto facultativo
        self.assertEqual(len(f), 10)

    def test_prazo_anpd_pula_feriado_nacional(self):
        # quarta 18/11/2026 + 3 dias úteis: 19 (qui), 20 é feriado, 23 (seg), 24 (ter)
        self.assertEqual(core.add_business_days(date(2026, 11, 18), 3), date(2026, 11, 24))
        # virada do ano: 30/12/2026 (qua) -> 31, 01/01 é feriado, 04, 05
        self.assertEqual(core.add_business_days(date(2026, 12, 30), 3), date(2027, 1, 5))

    def test_feriado_cadastrado_recalcula_prazo_e_fica_na_linha_do_tempo(self):
        iid = core.save_incident(self.db, 'Vazamento', 'Detecção', '', 'Alta', True, '02/03/2026')
        antes = core.incidents(self.db)[0]['anpd_deadline']
        self.assertEqual(antes, '2026-03-05')
        self.assertEqual(core.add_holiday(self.db, '04/03/2026', 'Feriado municipal', 'Municipal'), 1)
        self.assertEqual(core.incidents(self.db)[0]['anpd_deadline'], '2026-03-06')
        self.assertTrue(any('Prazo ANPD recalculado' in str(r) for r in core.incident_timeline(self.db, iid)))
        self.assertTrue(core.verify_chain(self.db, 'incident_log')[0])
        self.assertIn(('2026-03-04', 'Feriado municipal', 'Municipal'), core.holidays(self.db, 2026))
        self.assertEqual(core.remove_holiday(self.db, '2026-03-04'), 1)
        self.assertEqual(core.incidents(self.db)[0]['anpd_deadline'], '2026-03-05')
        with self.assertRaises(ValueError):
            core.add_holiday(self.db, '04/03/2026', 'X', 'Inventado')

    def test_comunicado_nao_e_recalculado(self):
        iid = core.save_incident(self.db, 'Vazamento', 'Detecção', '', 'Alta', True, '02/03/2026')
        core.mark_anpd_notified(self.db, iid, '03/03/2026')
        self.assertEqual(core.add_holiday(self.db, '04/03/2026', 'Municipal', 'Municipal'), 0)


class VariosComputadoresTests(Base):
    def test_pior_situacao_entre_computadores_e_comparacao_por_computador(self):
        core.save_collection(self.db, {'host': 'PC-A'}, {}, _resultados('OK'))
        core.save_collection(self.db, {'host': 'PC-B'}, {}, _resultados('Falha'), source='Importada')
        self.assertEqual(core.findings_by_subcategory(self.db), {'PR.IR-01': 'Falha'})
        hosts = core.collections_by_host(self.db)
        self.assertEqual({h[2] for h in hosts}, {'PC-A', 'PC-B'})
        # A não piorou só porque B (outro computador) tem falha
        self.assertEqual(core.compare_collections(self.db), [])
        core.save_collection(self.db, {'host': 'PC-A'}, {}, _resultados('Atenção'))
        changes = core.compare_collections(self.db)
        self.assertEqual([(c['host'], c['change']) for c in changes], [('PC-A', 'piorou')])
        self.assertEqual(len(core.collections_by_host(self.db)), 2)

    def test_coleta_importada_nao_conta_como_coleta_local(self):
        core.save_collection(self.db, {'host': 'PC-B'}, {}, _resultados('OK'), source='Importada')
        self.assertIsNone(core.last_collection_age_days(self.db))
        self.assertTrue(core.collection_needed(self.db))

    def test_importa_arquivo_do_coletor_avulso(self):
        raw = {'meta': {'host': 'PC-SEM-APP', 'user': 'PMGO\\fulano', 'admin': True},
               'firewall': [{'name': 'Public', 'enabled': False}], 'bitlocker': {'drive': 'C:', 'protection': 1}}
        arq = self.dir / 'coleta_PC-SEM-APP_20261123_1000.json'
        arq.write_text(json.dumps({'formato': core.COLLECTION_FORMAT, 'versao': 1, 'gerado': '2026-11-23T10:00:00',
                                   'dados': raw}), encoding='utf-8-sig')
        cid = core.import_collection(self.db, arq)
        head = [h for h in core.collections_by_host(self.db) if h[0] == cid][0]
        self.assertEqual((head[1], head[2], head[6]), ('2026-11-23T10:00:00', 'PC-SEM-APP', 'Importada'))
        self.assertEqual(core.findings_by_subcategory(self.db).get('PR.IR-01'), 'Falha')
        # embrulho do PowerShell 5.1 ({"value": [...], "Count": n}) é desfeito
        raw['nopwd'] = {'value': ['Convidado2'], 'Count': 1}
        arq.write_text(json.dumps({'formato': core.COLLECTION_FORMAT, 'dados': raw}), encoding='utf-8')
        core.import_collection(self.db, arq)
        contas = [f for f in core.findings_for(self.db, core.collections_by_host(self.db)[0][0]) if f[0] == 'accounts']
        self.assertIn('Convidado2', contas[0][3])
        ruim = self.dir / 'x.json'
        ruim.write_text('{"formato": "outro"}', encoding='utf-8')
        with self.assertRaises(ValueError):
            core.import_collection(self.db, ruim)
        ruim.write_text('não é json', encoding='utf-8')
        with self.assertRaises(ValueError):
            core.import_collection(self.db, ruim)

    def test_coletor_avulso_versionado_igual_ao_gerado(self):
        gerado = collector.standalone_script()
        self.assertIn(collector._PS.strip().splitlines()[3], gerado)
        self.assertIn('"formato":"scyber-nist-coleta"', gerado)
        self.assertEqual(gerado.count('$r | ConvertTo-Json -Depth 5 -Compress'), 1)
        self.assertTrue(gerado.isascii(), 'PowerShell 5.1 lê .ps1 sem BOM como ANSI: mantenha ASCII')
        no_disco = (APP_DIR / 'coletor_nist.ps1').read_text(encoding='utf-8-sig').replace('\r\n', '\n')
        self.assertEqual(no_disco, gerado, 'rode collector.standalone_script() e atualize coletor_nist.ps1')
        bat = (APP_DIR / 'coletar_nist_windows.bat').read_text(encoding='ascii').replace('\r\n', '\n')
        self.assertEqual(bat, collector.STANDALONE_BAT)


class EvidenciaSubcategoriaTests(Base):
    def test_anexa_lista_e_remove(self):
        eid = core.save_evidence(self.db, 'politica.pdf', 'a' * 64, '', 10, 'Política')
        self.assertTrue(core.link_evidence(self.db, 'GV.PO-01', eid))
        self.assertFalse(core.link_evidence(self.db, 'GV.PO-01', eid))          # sem duplicar
        self.assertEqual(core.evidence_counts(self.db), {'GV.PO-01': 1})
        self.assertEqual(core.evidence_for_sub(self.db, 'GV.PO-01')[0][1], 'politica.pdf')
        with self.assertRaises(ValueError):
            core.link_evidence(self.db, 'XX.YY-99', eid)
        with self.assertRaises(ValueError):
            core.link_evidence(self.db, 'GV.PO-01', 999)
        self.assertTrue(core.unlink_evidence(self.db, 'GV.PO-01', eid))
        self.assertEqual(core.evidence_counts(self.db), {})
        acoes = [r[4] for r in core.audit_list(self.db)]
        self.assertIn('Anexar evidência', acoes)
        self.assertIn('Remover evidência', acoes)


class BackupRetencaoTests(Base):
    def test_copia_automatica_diaria_guarda_sete(self):
        pasta = self.dir / 'backups'
        for i in range(10):
            core.auto_backup(self.db, today=date(2026, 11, 1) + timedelta(days=i))
        self.assertIsNone(core.auto_backup(self.db, today=date(2026, 11, 10)))      # mesmo dia: não repete
        nomes = sorted(p.name for p in pasta.glob('nist_auto_*.db'))
        self.assertEqual(len(nomes), core.AUTO_BACKUP_KEEP)
        self.assertEqual(nomes[-1], 'nist_auto_20261110.db')
        restaurado = core.connect(pasta / nomes[-1], KEY)          # abre com o mesmo certificado
        restaurado.close()

    def _encerrado(self, titulo, dias_atras):
        iid = core.save_incident(self.db, titulo, 'Detecção', '', 'Baixa', False)
        core.advance_incident(self.db, iid, 'Encerrado', 'fim')
        quando = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=dias_atras)).isoformat(timespec='seconds')
        self.db.execute('UPDATE incident_log SET at=? WHERE incident_id=?', (quando, iid))
        return iid

    def _rechain(self):
        fields = core._CHAINS['incident_log']
        prev = core.GENESIS
        for row in self.db.execute(f'SELECT id,{core._sel("incident_log", ",".join(fields))} FROM incident_log '
                                   'ORDER BY id').fetchall():
            h = core._entry_hash(prev, dict(zip(fields, row[1:], strict=True)))
            self.db.execute('UPDATE incident_log SET prev_hash=?, hash=? WHERE id=?', (prev, h, row[0]))
            prev = h
        self.db.commit()

    def test_retencao_exclui_so_encerrados_antigos_e_mantem_cadeia(self):
        velho = self._encerrado('Antigo', 2000)
        self._encerrado('Recente', 10)
        aberto = core.save_incident(self.db, 'Aberto', 'Detecção', '', 'Alta', False)
        eid = core.save_evidence(self.db, 'log.txt', 'b' * 64, '', 1, 'log', incident_id=velho)
        self._rechain()       # as datas foram alteradas no teste; refaz a cadeia como se fossem originais
        arquivo = self.dir / 'retencao.db'
        self.assertEqual(core.purge_closed_incidents(self.db, 1825, arquivo), 1)
        self.assertTrue(arquivo.exists())
        titulos = {i['title'] for i in core.incidents(self.db)}
        self.assertEqual(titulos, {'Recente', 'Aberto'})
        self.assertTrue(core.verify_chain(self.db, 'incident_log')[0])
        self.assertIsNone(core.evidence(self.db, eid)['incident_id'])
        self.assertTrue(core.incident_timeline(self.db, aberto))
        self.assertEqual(core.audit_list(self.db)[0][3:5], ('Retenção', 'Excluir incidentes encerrados'))
        self.assertEqual(core.purge_closed_incidents(self.db, 1825), 0)
        with self.assertRaises(ValueError):
            core.purge_closed_incidents(self.db, 5)

    def test_retencao_bloqueada_com_cadeia_adulterada(self):
        self._encerrado('Antigo', 2000)
        self._rechain()
        self.db.execute("UPDATE incident_log SET note=? WHERE id=1", (self.db.E('alterado'),))
        self.db.commit()
        with self.assertRaises(ValueError):
            core.purge_closed_incidents(self.db, 1825)
        self.assertEqual(len(core.incidents(self.db)), 1)


class AssinaturaTests(unittest.TestCase):
    def test_confere_e_detecta_alteracao(self):
        cert, key = _certificado()
        cms = _assinador(cert, key)(b'dados')
        info = signing.verify_detached(b'dados', cms)
        self.assertEqual(info['thumb'], signing.thumbprint(cert))
        self.assertEqual(info['subject'], 'S-Cyber-PM-NIST-2.0')
        with self.assertRaises(signing.SignatureError):
            signing.verify_detached(b'dadoz', cms)
        with self.assertRaises(signing.SignatureError):
            signing.verify_detached(b'dados', cms[:-10])
        with self.assertRaises(signing.SignatureError):
            signing.verify_detached(b'dados', b'\x30\x03\x02\x01\x01')


class PacoteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.origem = core.connect(self.dir / 'a.db', KEY)
        self.destino = core.connect(self.dir / 'b.db', crypto.derive_key(os.urandom(32)))
        for db in (self.origem, self.destino):
            db.actor = 'teste'
        self.cert, self.key = _certificado()
        self.thumb = signing.thumbprint(self.cert)
        core.save_sub_assessment(self.origem, 'PR.DS-01', 2, 3)
        core.save_risk(self.origem, 'Vazamento de dados pessoais do efetivo', 'Dados', 3, 3, 'PR')
        core.save_incident(self.origem, 'Phishing no e-mail do comando', 'Detecção', 'Fulano clicou', 'Alta', True,
                           (date.today() - timedelta(days=10)).strftime('%d/%m/%Y'))
        core.save_collection(self.origem, {'host': 'PC-A'}, {}, _resultados('Falha'))
        self.arq = self.dir / 'pacote.scnist'

    def tearDown(self):
        self.origem.close()
        self.destino.close()
        self.tmp.cleanup()

    def test_gera_importa_e_consolida_sem_textos(self):
        info = package.build(self.origem, self.arq, '1º BPM', SENHA, _assinador(self.cert, self.key))
        self.assertEqual(info['thumb'], self.thumb)
        bruto = self.arq.read_text(encoding='utf-8')
        for segredo in ('Vazamento', 'Phishing', 'Fulano', '1º BPM', 'S-Cyber-PM-NIST-2.0'):
            self.assertNotIn(segredo, bruto)                     # tudo cifrado, até o assinante
        dados, _, _ = package.read(self.arq, SENHA)
        texto = json.dumps(dados, ensure_ascii=False)
        for segredo in ('Vazamento', 'Phishing', 'Fulano'):
            self.assertNotIn(segredo, texto)                     # minimização: sem títulos nem notas
        r = package.import_package(self.destino, self.arq, SENHA, [self.thumb.lower()])
        self.assertTrue(r['trusted'])
        view = core.consolidated_view(self.destino)
        self.assertEqual([v['unit'] for v in view], ['Este computador', '1º BPM', 'MÉDIA'])
        bpm = view[1]
        self.assertEqual((bpm['high_risks'], bpm['open_incidents'], bpm['anpd_overdue']), (1, 1, 1))
        self.assertGreater(bpm['maturity']['PR'], 0)
        with self.assertRaises(ValueError):                      # o mesmo pacote duas vezes
            package.import_package(self.destino, self.arq, SENHA, [self.thumb])
        self.assertEqual(core.audit_list(self.destino)[0][3:5], ('Consolidação', 'Importar pacote'))

    def test_relatorio_com_consolidacao_varios_computadores_e_textos_especiais(self):
        package.build(self.origem, self.arq, '1º BPM', SENHA, _assinador(self.cert, self.key))
        package.import_package(self.destino, self.arq, SENHA, [self.thumb])
        core.save_risk(self.destino, 'Senha <fraca> & "exposta"', 'Contas', 2, 2, 'PR')
        core.save_collection(self.destino, {'host': 'PC-1'}, {}, _resultados('OK'))
        core.save_collection(self.destino, {'host': 'PC-2'}, {}, _resultados('Falha'), source='Importada')
        eid = core.save_evidence(self.destino, 'politica<v2>.pdf', 'c' * 64, '', 1, 'Política')
        core.link_evidence(self.destino, 'GV.PO-01', eid)
        pdf = report.build(self.destino, self.dir / 'r.pdf', 'Unidade <teste>', 'Sgt')
        self.assertGreater(Path(pdf).stat().st_size, 5000)

    def test_recusas(self):
        package.build(self.origem, self.arq, '1º BPM', SENHA, _assinador(self.cert, self.key))
        with self.assertRaises(ValueError):
            package.import_package(self.destino, self.arq, 'Senha-Errada-123', [self.thumb])
        with self.assertRaises(PermissionError):
            package.import_package(self.destino, self.arq, SENHA, ['0' * 40])
        r = package.import_package(self.destino, self.arq, SENHA, [], allow_untrusted=True)
        self.assertFalse(r['trusted'])
        self.assertIn('FORA da lista', core.audit_list(self.destino)[0][6])
        with self.assertRaises(ValueError):                      # o próprio pacote
            package.import_package(self.origem, self.arq, SENHA, [self.thumb])
        with self.assertRaises(ValueError):
            package.build(self.origem, self.dir / 'y.scnist', 'X', 'curta', _assinador(self.cert, self.key))

    def test_assinatura_trocada_e_recusada(self):
        outro_cert, outro_key = _certificado('Intruso')

        def assinador_falso(data):
            return _assinador(outro_cert, outro_key)(data + b' ')      # assina outro conteúdo
        with self.assertRaises(signing.SignatureError):
            package.build(self.origem, self.arq, '1º BPM', SENHA, assinador_falso)
        self.assertFalse(self.arq.exists())


class AvisosTests(Base):
    def test_avisos_de_abertura(self):
        hoje = date(2026, 11, 23)
        core.save_incident(self.db, 'Vazamento', 'Detecção', '', 'Alta', True, '16/11/2026')
        core.save_sub_assessment(self.db, 'PR.DS-01', 1, 3, 'Sgt', '01/11/2026')
        textos = [t for t, _ in notificacoes.avisos(self.db, '2027-01-10', hoje)]
        self.assertTrue(any(t.startswith('ANPD: incidente #1 com prazo VENCIDO') for t in textos))
        self.assertIn('Plano de ação: 1 ação(ões) com prazo vencido', textos)
        self.assertTrue(any('vence em 48 dia(s)' in t for t in textos))
        self.assertFalse(any('Vazamento' in t for t in textos))            # sem títulos na notificação
        self.assertEqual(notificacoes.avisos(self.db, '2027-12-31', date(2026, 10, 1)), [])

    def test_rotina_de_entrada_faz_copia_e_devolve_avisos(self):
        caminho = self.dir / 'nist.db'
        criado, avisos = notificacoes.rotina_de_entrada(caminho, KEY, 'teste', None, date(2026, 11, 23))
        self.assertTrue(criado and Path(criado).exists())
        self.assertEqual(avisos, [])
        self.assertFalse(notificacoes.toast([]))


class IntegracaoTests(unittest.TestCase):
    def test_rotina_de_entrada_ligada_ao_login_e_aba_no_menu(self):
        app = (APP_DIR / 'appSCyberPM.py').read_text(encoding='utf-8')
        self.assertIn('root.after(2000, nist.ao_entrar)', app)
        self.assertIn('"Consolidação"', app)
        mod = (APP_DIR / 'modNist.py').read_text(encoding='utf-8')
        self.assertIn('preparar_rotina_de_entrada', mod)
        self.assertIn('threading.Thread(target=trabalho, daemon=True)', mod)
        form = (APP_DIR / 'formNISTIntelligence.py').read_text(encoding='utf-8')
        self.assertIn('signing.windows_signer(thumb)', form)
        self.assertIn('trusted_thumbs=_certificados_autorizados()', form)
        main = (APP_DIR / 'nist_intelligence' / 'main.py').read_text(encoding='utf-8')
        self.assertIn("self.add_tab('Consolidação')", main)


if __name__ == '__main__':
    unittest.main()
