"""Fase 6: indicadores de evolução — só contagens do que foi registrado, sem nota de segurança."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from nist_intelligence import indicadores as I  # noqa: E402
from test_fase4 import RAW_RUIM, Base, corrigido  # noqa: E402


class IndicadoresTests(Base):
    def test_sem_diagnostico_nao_vira_resultado_bom(self):
        ind = I.indicadores(self.db)
        self.assertEqual(ind['diagnosticos'], 0)
        self.assertIsNone(ind['ultimo_diagnostico'])
        frases = ' '.join(I.leitura(ind))
        self.assertIn('ainda não foi avaliada', frases)
        self.assertNotIn('sem falha detectada.', frases)
        self.assertIn('sem avaliação não é o mesmo que sem problema', frases)

    def test_evolucao_entre_dois_diagnosticos_do_mesmo_ativo(self):
        self.rodar(RAW_RUIM)
        self.rodar(corrigido())
        serie = I.evolucao(self.db)
        self.assertEqual(len(serie), 2)
        antes, depois = serie
        self.assertLessEqual(antes['quando'], depois['quando'])
        self.assertGreater(antes['falha'] + antes['atencao'], depois['falha'] + depois['atencao'])
        self.assertGreaterEqual(antes['prioritarias'], depois['prioritarias'])
        for linha in serie:      # indisponível nunca conta como verificada
            self.assertEqual(linha['verificadas'], linha['ok'] + linha['atencao'] + linha['falha'])
            self.assertEqual(linha['total'], linha['verificadas'] + linha['indisponivel'])
        ind = I.indicadores(self.db)
        self.assertEqual(ind['diagnosticos'], 2)
        self.assertEqual(ind['ativos_avaliados'], 1)
        comp = ind['comparacao']['tendencias']
        self.assertGreaterEqual(comp.get('Melhorou', 0), 3)        # firewall, RDP, SMBv1 (e portas)
        self.assertEqual(comp.get('Piorou', 0), 0)
        frases = ' '.join(I.leitura(ind))
        self.assertIn('melhorou', frases)
        self.assertIn('não contam como aprovadas', frases)           # restorepoints: Acesso negado

    def test_metodologia_documentada_e_sem_nota(self):
        self.assertIn('Nenhum número aqui é uma nota de segurança', I.METODOLOGIA)
        self.rodar(RAW_RUIM)
        ind = I.indicadores(self.db)
        self.assertFalse(any('%' in str(v) for v in ind.values() if isinstance(v, str)))
        self.assertGreater(ind['achados_suspeitos'], 0)


if __name__ == '__main__':
    unittest.main()
