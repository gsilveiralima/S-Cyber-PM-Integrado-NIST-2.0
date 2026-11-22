"""Catálogo NIST Cybersecurity Framework 2.0 (NIST CSWP 29, fev/2024).

Funções, 22 categorias e 106 subcategorias com os identificadores oficiais.
As descrições são traduções livres e resumidas: o texto oficial (em inglês)
continua sendo a referência. O NIST CSF é obra do governo dos EUA, de domínio público.
"""

FUNCTIONS = [('GV', 'Governar'), ('ID', 'Identificar'), ('PR', 'Proteger'),
             ('DE', 'Detectar'), ('RS', 'Responder'), ('RC', 'Recuperar')]

CATEGORIES = [
 ('GV.OC', 'Contexto organizacional'), ('GV.RM', 'Estratégia de gestão de riscos'),
 ('GV.RR', 'Papéis, responsabilidades e autoridades'), ('GV.PO', 'Políticas'),
 ('GV.OV', 'Supervisão'), ('GV.SC', 'Risco cibernético na cadeia de suprimentos'),
 ('ID.AM', 'Gestão de ativos'), ('ID.RA', 'Avaliação de riscos'), ('ID.IM', 'Melhoria'),
 ('PR.AA', 'Identidade, autenticação e controle de acesso'),
 ('PR.AT', 'Conscientização e treinamento'), ('PR.DS', 'Segurança de dados'),
 ('PR.PS', 'Segurança de plataformas'), ('PR.IR', 'Resiliência da infraestrutura tecnológica'),
 ('DE.CM', 'Monitoramento contínuo'), ('DE.AE', 'Análise de eventos adversos'),
 ('RS.MA', 'Gestão de incidentes'), ('RS.AN', 'Análise de incidentes'),
 ('RS.CO', 'Comunicação e notificação de resposta'), ('RS.MI', 'Mitigação de incidentes'),
 ('RC.RP', 'Execução do plano de recuperação'), ('RC.CO', 'Comunicação na recuperação'),
]

SUBCATEGORIES = [
 # GOVERNAR — Contexto organizacional
 ('GV.OC-01', 'A missão da organização é entendida e orienta a gestão de riscos cibernéticos'),
 ('GV.OC-02', 'Partes interessadas internas e externas e suas expectativas são conhecidas'),
 ('GV.OC-03', 'Requisitos legais, regulatórios e contratuais (inclusive privacidade/LGPD) são entendidos e gerenciados'),
 ('GV.OC-04', 'Objetivos, capacidades e serviços críticos dos quais terceiros dependem são conhecidos e comunicados'),
 ('GV.OC-05', 'Resultados, capacidades e serviços dos quais a organização depende são conhecidos e comunicados'),
 # Estratégia de gestão de riscos
 ('GV.RM-01', 'Objetivos de gestão de riscos são definidos e acordados pelas partes interessadas'),
 ('GV.RM-02', 'Apetite e tolerância a risco são definidos, comunicados e mantidos'),
 ('GV.RM-03', 'A gestão de riscos cibernéticos integra a gestão de riscos corporativa'),
 ('GV.RM-04', 'Direção estratégica com opções de resposta a risco é definida e comunicada'),
 ('GV.RM-05', 'Linhas de comunicação sobre riscos cibernéticos são estabelecidas, inclusive com terceiros'),
 ('GV.RM-06', 'Método padronizado para calcular, documentar, categorizar e priorizar riscos é definido'),
 ('GV.RM-07', 'Oportunidades estratégicas (riscos positivos) são caracterizadas e consideradas'),
 # Papéis, responsabilidades e autoridades
 ('GV.RR-01', 'A liderança assume responsabilidade pelo risco cibernético e promove uma cultura consciente de riscos'),
 ('GV.RR-02', 'Papéis, responsabilidades e autoridades de gestão de riscos são definidos, comunicados e aplicados'),
 ('GV.RR-03', 'Recursos adequados são alocados conforme a estratégia e as políticas de risco'),
 ('GV.RR-04', 'Segurança cibernética é incluída nas práticas de gestão de pessoas'),
 # Políticas
 ('GV.PO-01', 'Política de gestão de riscos cibernéticos é definida, comunicada e aplicada'),
 ('GV.PO-02', 'A política é revisada, atualizada e aplicada conforme mudanças de requisitos, ameaças e tecnologia'),
 # Supervisão
 ('GV.OV-01', 'Os resultados da estratégia de gestão de riscos são revisados para ajustar a direção'),
 ('GV.OV-02', 'A estratégia é revisada e ajustada para cobrir requisitos e riscos organizacionais'),
 ('GV.OV-03', 'O desempenho da gestão de riscos cibernéticos é avaliado e revisado'),
 # Cadeia de suprimentos
 ('GV.SC-01', 'Programa, estratégia, objetivos e políticas de risco da cadeia de suprimentos são estabelecidos'),
 ('GV.SC-02', 'Papéis de segurança de fornecedores, clientes e parceiros são definidos e coordenados'),
 ('GV.SC-03', 'A gestão de risco da cadeia de suprimentos integra a gestão de riscos da organização'),
 ('GV.SC-04', 'Fornecedores são conhecidos e priorizados por criticidade'),
 ('GV.SC-05', 'Requisitos de segurança são incluídos em contratos e acordos com fornecedores'),
 ('GV.SC-06', 'Planejamento e diligência prévia reduzem riscos antes de contratar fornecedores'),
 ('GV.SC-07', 'Riscos de cada fornecedor são identificados, priorizados, avaliados e monitorados'),
 ('GV.SC-08', 'Fornecedores relevantes participam do planejamento, resposta e recuperação de incidentes'),
 ('GV.SC-09', 'Práticas de segurança da cadeia de suprimentos são monitoradas durante o ciclo de vida'),
 ('GV.SC-10', 'Planos cobrem atividades após o fim de parcerias ou contratos'),
 # IDENTIFICAR — Gestão de ativos
 ('ID.AM-01', 'Inventários de hardware são mantidos'),
 ('ID.AM-02', 'Inventários de software, serviços e sistemas são mantidos'),
 ('ID.AM-03', 'Comunicações de rede e fluxos de dados autorizados são representados e mantidos'),
 ('ID.AM-04', 'Inventários de serviços prestados por fornecedores são mantidos'),
 ('ID.AM-05', 'Ativos são priorizados por classificação, criticidade, recursos e impacto na missão'),
 ('ID.AM-07', 'Inventários de dados e metadados de tipos de dados designados são mantidos'),
 ('ID.AM-08', 'Sistemas, hardware, software, serviços e dados são gerenciados durante todo o ciclo de vida'),
 # Avaliação de riscos
 ('ID.RA-01', 'Vulnerabilidades em ativos são identificadas, validadas e registradas'),
 ('ID.RA-02', 'Inteligência de ameaças cibernéticas é recebida de fóruns e fontes de compartilhamento'),
 ('ID.RA-03', 'Ameaças internas e externas são identificadas e registradas'),
 ('ID.RA-04', 'Impactos e probabilidades de ameaças explorarem vulnerabilidades são identificados'),
 ('ID.RA-05', 'Ameaças, vulnerabilidades, probabilidades e impactos são usados para priorizar a resposta a riscos'),
 ('ID.RA-06', 'Respostas a riscos são escolhidas, priorizadas, planejadas, acompanhadas e comunicadas'),
 ('ID.RA-07', 'Mudanças e exceções são gerenciadas, avaliadas quanto ao risco, registradas e acompanhadas'),
 ('ID.RA-08', 'Há processos para receber, analisar e responder a divulgações de vulnerabilidades'),
 ('ID.RA-09', 'A autenticidade e integridade de hardware e software são avaliadas antes da aquisição e uso'),
 ('ID.RA-10', 'Fornecedores críticos são avaliados antes da aquisição'),
 # Melhoria
 ('ID.IM-01', 'Melhorias são identificadas a partir de avaliações'),
 ('ID.IM-02', 'Melhorias são identificadas a partir de testes e exercícios de segurança'),
 ('ID.IM-03', 'Melhorias são identificadas na execução de processos, procedimentos e atividades'),
 ('ID.IM-04', 'Planos de resposta a incidentes e outros planos de segurança são estabelecidos, comunicados, mantidos e melhorados'),
 # PROTEGER — Identidade, autenticação e controle de acesso
 ('PR.AA-01', 'Identidades e credenciais de usuários, serviços e hardware autorizados são gerenciadas'),
 ('PR.AA-02', 'Identidades são comprovadas e vinculadas a credenciais conforme o contexto de uso'),
 ('PR.AA-03', 'Usuários, serviços e hardware são autenticados'),
 ('PR.AA-04', 'Asserções de identidade são protegidas, transmitidas e verificadas'),
 ('PR.AA-05', 'Permissões e autorizações são definidas em política, gerenciadas, aplicadas e revisadas (menor privilégio e separação de funções)'),
 ('PR.AA-06', 'O acesso físico a ativos é gerenciado, monitorado e aplicado conforme o risco'),
 # Conscientização e treinamento
 ('PR.AT-01', 'O pessoal recebe conscientização e treinamento para executar tarefas gerais com atenção aos riscos cibernéticos'),
 ('PR.AT-02', 'Pessoas em funções especializadas recebem treinamento específico'),
 # Segurança de dados
 ('PR.DS-01', 'A confidencialidade, integridade e disponibilidade dos dados em repouso são protegidas'),
 ('PR.DS-02', 'A confidencialidade, integridade e disponibilidade dos dados em trânsito são protegidas'),
 ('PR.DS-10', 'A confidencialidade, integridade e disponibilidade dos dados em uso são protegidas'),
 ('PR.DS-11', 'Backups de dados são criados, protegidos, mantidos e testados'),
 # Segurança de plataformas
 ('PR.PS-01', 'Práticas de gerenciamento de configuração são estabelecidas e aplicadas'),
 ('PR.PS-02', 'Software é mantido, substituído e removido conforme o risco'),
 ('PR.PS-03', 'Hardware é mantido, substituído e removido conforme o risco'),
 ('PR.PS-04', 'Registros de log são gerados e disponibilizados para monitoramento contínuo'),
 ('PR.PS-05', 'A instalação e execução de software não autorizado são impedidas'),
 ('PR.PS-06', 'Práticas de desenvolvimento seguro são integradas e seu desempenho é monitorado'),
 # Resiliência da infraestrutura
 ('PR.IR-01', 'Redes e ambientes são protegidos contra acesso lógico e uso não autorizados'),
 ('PR.IR-02', 'Os ativos de tecnologia são protegidos contra ameaças ambientais'),
 ('PR.IR-03', 'Mecanismos garantem a resiliência em situações normais e adversas'),
 ('PR.IR-04', 'Há capacidade de recursos adequada para garantir a disponibilidade'),
 # DETECTAR — Monitoramento contínuo
 ('DE.CM-01', 'Redes e serviços de rede são monitorados para encontrar eventos potencialmente adversos'),
 ('DE.CM-02', 'O ambiente físico é monitorado para encontrar eventos potencialmente adversos'),
 ('DE.CM-03', 'A atividade de pessoal e o uso de tecnologia são monitorados para encontrar eventos adversos'),
 ('DE.CM-06', 'Atividades e serviços de prestadores externos são monitorados'),
 ('DE.CM-09', 'Hardware, software, ambientes de execução e dados são monitorados (inclusive código malicioso)'),
 # Análise de eventos adversos
 ('DE.AE-02', 'Eventos potencialmente adversos são analisados para entender atividades associadas'),
 ('DE.AE-03', 'Informações de várias fontes são correlacionadas'),
 ('DE.AE-04', 'O impacto estimado e o escopo dos eventos adversos são entendidos'),
 ('DE.AE-06', 'Informações sobre eventos adversos são fornecidas à equipe e às ferramentas autorizadas'),
 ('DE.AE-07', 'Inteligência de ameaças e outras informações contextuais são integradas à análise'),
 ('DE.AE-08', 'Incidentes são declarados quando eventos adversos atendem aos critérios definidos'),
 # RESPONDER — Gestão de incidentes
 ('RS.MA-01', 'O plano de resposta a incidentes é executado em coordenação com terceiros relevantes'),
 ('RS.MA-02', 'Relatos de incidentes são triados e validados'),
 ('RS.MA-03', 'Incidentes são categorizados e priorizados'),
 ('RS.MA-04', 'Incidentes são escalados ou elevados conforme necessário'),
 ('RS.MA-05', 'Os critérios para iniciar a recuperação do incidente são aplicados'),
 # Análise de incidentes
 ('RS.AN-03', 'É feita análise para estabelecer o que ocorreu e a causa raiz do incidente'),
 ('RS.AN-06', 'As ações da investigação são registradas e a integridade e procedência dos registros são preservadas'),
 ('RS.AN-07', 'Dados e metadados do incidente são coletados, com integridade e procedência preservadas'),
 ('RS.AN-08', 'A magnitude do incidente é estimada e validada'),
 # Comunicação
 ('RS.CO-02', 'Partes interessadas internas e externas são notificadas sobre incidentes'),
 ('RS.CO-03', 'Informações são compartilhadas com as partes interessadas designadas'),
 # Mitigação
 ('RS.MI-01', 'Incidentes são contidos'),
 ('RS.MI-02', 'Incidentes são erradicados'),
 # RECUPERAR — Execução do plano
 ('RC.RP-01', 'A parte de recuperação do plano de resposta é executada após o início no processo de resposta'),
 ('RC.RP-02', 'Ações de recuperação são selecionadas, delimitadas, priorizadas e executadas'),
 ('RC.RP-03', 'A integridade de backups e outros recursos de restauração é verificada antes de usá-los'),
 ('RC.RP-04', 'Funções críticas e a gestão de riscos são consideradas para estabelecer normas operacionais pós-incidente'),
 ('RC.RP-05', 'A integridade dos ativos restaurados é verificada e a operação normal é confirmada'),
 ('RC.RP-06', 'O fim da recuperação é declarado conforme critérios e a documentação é concluída'),
 # Comunicação na recuperação
 ('RC.CO-03', 'Atividades e progresso da recuperação são comunicados às partes interessadas designadas'),
 ('RC.CO-04', 'Atualizações públicas sobre a recuperação são compartilhadas por métodos e mensagens aprovados'),
]

# Níveis de maturidade usados na avaliação (escala ordinal 0–4).
MATURITY = [
    (0, 'Inexistente'),
    (1, 'Inicial (informal)'),
    (2, 'Parcial (documentado em parte)'),
    (3, 'Implementado (documentado e aplicado)'),
    (4, 'Gerenciado (medido e melhorado)'),
]

# Níveis de implementação (Tiers) do CSF 2.0 — postura organizacional por função.
TIERS = [(1, 'Parcial'), (2, 'Informado por riscos'), (3, 'Repetível'), (4, 'Adaptativo')]


def category_of(sub_code):
    return sub_code.split('-')[0]


def function_of(code):
    return code.split('.')[0]


SUB_BY_CATEGORY = {}
for _code, _desc in SUBCATEGORIES:
    SUB_BY_CATEGORY.setdefault(category_of(_code), []).append((_code, _desc))
del _code, _desc
