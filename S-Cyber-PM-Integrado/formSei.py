# ==============================================================================
#  S-Cyber PM - Cryptography and Digital Certificate Framework
# ------------------------------------------------------------------------------
#  Arquivo     : formSei.py
#  Descrição   : Análise de processos do SEI por automação do navegador
#                (Selenium) - somente leitura
#  Tipo        : Formulário (tkinter)
#  Versão      : ver formAbout.APP_VERSAO (fonte única da versão)
#  Revisão     : 2026-11-19
#  Autores     : MAJ Daniel Medrado - PMGO
#                MAJ Leonidio Alves de Moraes Junior - PMGO
#                SGT Gabriel Silvieira Lima - PMGO
#  Instituição : Polícia Militar do Estado de Goiás
#  Contato     : leonidio.moraes@goias.gov.br
#  Licença     : Uso interno da instituição. Proibida a redistribuição sem
#                autorização.
#  Requisitos  : Python 3.11+ (64 bits), Windows 10/11, selenium>=4.25
#  Codificação : UTF-8
# ------------------------------------------------------------------------------
#  Histórico de revisões
#    Versão  Data        Alteração
#    1.4     2026-11-20  Botão Fechar sai do rodapé e vai para o canto superior
#                        direito do cabeçalho
#    1.4     2026-11-19  Login automático pelo Selenium com as credenciais
#                        informadas no formulário (captcha/2FA manual)
#    1.4     2026-11-19  Automação pelo Selenium (Chrome/Edge): login manual no
#                        navegador controlado, leitura do Controle de
#                        Processos, pesquisa rápida, árvore de documentos,
#                        andamentos e conteúdo de documentos. Somente leitura.
#    1.4     2026-11-15  Usa formExploreSEI.py (antigo sei_cliente.py)
#                        Cabeçalho padrão de identificação e revisão
# ==============================================================================
"""
S-Cyber PM - Formulário formSei: análise de processos do SEI pelo navegador
controlado via Selenium (SOMENTE LEITURA).

Como funciona
-------------
1. Informe usuário, senha (e o órgão, se a tela de login tiver a lista) e
   clique em "Entrar no SEI": o Selenium abre o Chrome ou o Edge com um
   perfil próprio do S-Cyber PM (em %LOCALAPPDATA%\\SCyberPM), preenche a
   página de login do SEI e entra. A senha fica só na memória durante o
   login, é digitada apenas no campo da página do SEI e não é gravada.
   Se houver captcha ou código de 2 fatores, você conclui na janela do
   navegador e o programa continua sozinho.
   "Abrir navegador" apenas abre a janela, para login manual.
   Alternativa: "Conectar (porta)" liga-se a um Chrome/Edge que você abriu
   com depuração remota, por exemplo:
       chrome.exe --remote-debugging-port=9222 --user-data-dir=C:\\SeiPerfil
   (O Chrome não permite automação na janela comum já aberta; por isso a
   sessão do seu navegador habitual não pode ser reaproveitada.)
2. "Ler Controle de Processos" lê as tabelas de Recebidos/Gerados da unidade.
3. "Analisar processo" lê a árvore de documentos e os andamentos.
   Duplo clique num documento lê o texto dele.

Garantias de somente leitura
----------------------------
- O programa nunca clica em botões do SEI. Ele só navega (driver.get) para
  links já presentes nas páginas e cuja ação ("acao=") está na lista
  ACOES_LEITURA; qualquer outra ação é recusada.
- A pesquisa rápida apenas preenche e envia o campo de pesquisa do topo.
- Atenção: abrir um processo que aparece em vermelho ("não visualizado") faz
  o SEI marcá-lo como visualizado na unidade - exatamente como acontece ao
  abri-lo à mão. O programa pede confirmação antes nesse caso.
- O trabalho é feito numa aba separada; a aba em que você fez login não é
  alterada.

Observação: o SEI tem várias versões e cada órgão personaliza o layout. Os
seletores seguem o padrão do SEI 4.x e podem precisar de ajuste.

Uso dentro da aplicação:
    from formSei import FormSei
    FormSei(root)

Uso sozinho (para testar):
    python formSei.py
"""

import os
import re
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, ttk
from urllib.parse import parse_qs, urlsplit

from modRecursos import botao_fechar_cabecalho, centralizar

TEMPO_ESPERA = 25            # segundos para cada página/iframe carregar
LIMITE_TEXTO_DOC = 60000     # caracteres lidos de um documento
TEMPO_LOGIN = 180            # segundos para concluir o login (inclui captcha/2FA manual)

# Ações do SEI que apenas exibem informação. Só para estas o programa navega.
ACOES_LEITURA = {
    "procedimento_controlar",
    "procedimento_trabalhar",
    "procedimento_visualizar",
    "arvore_visualizar",
    "documento_visualizar",
    "protocolo_visualizar",
    "procedimento_consultar_historico",
    "procedimento_consultar_andamento",
    "protocolo_pesquisa_rapida",
}


class ErroSei(Exception):
    pass


# ==========================================================
# SCRIPTS EXECUTADOS NA PÁGINA (apenas leem o DOM)
# ==========================================================

JS_CONTROLE = r"""
const out = [];
const vistos = new Set();
const dica = (a) => {
  const mo = (a.getAttribute('onmouseover') || '');
  const m = mo.match(/infraTooltipMostrar\(\s*'((?:[^'\\]|\\.)*)'\s*,\s*'((?:[^'\\]|\\.)*)'/);
  const limpa = (s) => s.replace(/\\(.)/g, '$1').replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
  return m ? [limpa(m[1]), limpa(m[2])] : [(a.title || '').trim(), ''];
};
const ler = (raiz, secao) => {
  for (const a of raiz.querySelectorAll("a[href*='acao=procedimento_trabalhar']")) {
    const numero = a.textContent.replace(/\s+/g, ' ').trim();
    if (!numero || vistos.has(a.href)) continue;
    vistos.add(a.href);
    const tr = a.closest('tr');
    const [esp, tipo] = dica(a);
    let atrib = '', marc = [];
    if (tr) {
      atrib = [...tr.querySelectorAll("a[href*='atribu'], a.ancoraSigla")]
                .map(x => x.textContent.trim()).filter(Boolean).join(', ');
      marc = [...tr.querySelectorAll('img, a[onmouseover]')]
                .filter(x => x !== a)
                .map(x => {
                  if (x.tagName === 'IMG') return (x.title || x.alt || '').trim();
                  const d = dica(x); return d[0];
                })
                .filter(Boolean);
    }
    const cls = a.className || '';
    out.push({
      numero, href: a.href, secao, tipo, especificacao: esp, atribuicao: atrib,
      marcadores: [...new Set(marc)].join('; '),
      nao_visualizado: /NaoVisualizado/i.test(cls),
    });
  }
};
const tabelas = [['tblProcessosRecebidos', 'Recebidos'], ['tblProcessosGerados', 'Gerados'],
                 ['tblProcessosDetalhado', 'Detalhado']];
for (const [id, sec] of tabelas) { const t = document.getElementById(id); if (t) ler(t, sec); }
ler(document, 'Outros');
return out;
"""

JS_ARVORE = r"""
const nos = (typeof Nos !== 'undefined' && Array.isArray(Nos)) ? Nos.filter(Boolean) : [];
const porId = {};
for (const n of nos) { if (n && n.id !== undefined) porId[String(n.id)] = n; }
const hrefDe = (n) => {
  if (!n) return '';
  for (const k of Object.keys(n)) {
    const v = n[k];
    if (typeof v === 'string' && v.indexOf('controlador.php') >= 0) return new URL(v, location.href).href;
  }
  return '';
};
const r = [];
for (const a of document.querySelectorAll("a[id^='anchor']")) {
  const id = a.id.substring(6);
  if (!id) continue;
  const span = document.getElementById('span' + id) || a.querySelector('span');
  const texto = (span ? span.textContent : a.textContent).replace(/\s+/g, ' ').trim();
  if (!texto) continue;
  const n = porId[id];
  let nivel = 0;
  if (n) {
    let p = n, guarda = 0;
    while (p && guarda++ < 50) {
      const pai = p.idPai !== undefined ? p.idPai : p.pai;
      if (pai === null || pai === undefined || pai === '') break;
      p = porId[String(pai)]; if (p) nivel++;
    }
  } else {
    let el = a.parentElement;
    while (el) { if (el.tagName === 'DIV' && /^div\d/.test(el.id || '')) nivel++; el = el.parentElement; }
  }
  let href = a.getAttribute('href') || '';
  href = (href && !href.startsWith('javascript') && href !== '#') ? a.href : hrefDe(n);
  const icone = document.getElementById('icon' + id);
  r.push({
    id, texto, nivel, href,
    tipo: n && n.tipo ? String(n.tipo) : '',
    titulo: (a.title || (span && span.title) || (icone && icone.title) || '').trim(),
  });
}
let andamento = '';
for (const a of document.querySelectorAll('a[href]')) {
  if (/acao=procedimento_consultar_(historico|andamento)/.test(a.getAttribute('href'))) { andamento = a.href; break; }
}
if (!andamento && nos.length) {
  for (const n of nos) { const h = hrefDe(n); if (/procedimento_consultar_(historico|andamento)/.test(h)) { andamento = h; break; } }
}
return {itens: r, andamento};
"""

JS_HISTORICO = r"""
// Linhas diretas da tabela (sem descer em tabelas internas)
const linhasDe = (t) => {
  const out = [];
  for (const tr of t.rows) {
    const tds = [...tr.cells].filter(c => c.tagName === 'TD')
                  .map(td => td.innerText.replace(/\s+/g, ' ').trim());
    if (tds.length >= 3 && /\d{2}\/\d{2}\/\d{4}/.test(tds.join(' '))) out.push(tds);
  }
  return out;
};
const cand = [];
const fixa = document.getElementById('tblHistorico');
if (fixa) cand.push(fixa);
for (const tb of document.querySelectorAll('table')) {
  const cab = ([...tb.querySelectorAll('th, caption')].map(x => x.innerText).join(' ') ||
               tb.innerText.slice(0, 400)).toLowerCase();
  if (cab.includes('unidade') && (cab.includes('descri') || cab.includes('data'))) cand.push(tb);
}
let melhor = [];
for (const t of cand) { const l = linhasDe(t); if (l.length > melhor.length) melhor = l; }
return melhor;
"""

# Elemento "Consultar Andamento". No SEI 4.x não fica na árvore, e sim na barra
# de ferramentas do processo (que aparece ao abrir o nó raiz); por isso este
# script também reconhece o ícone da barra (imagem com título "Consultar
# Andamento"). É rodado em cada quadro até achar o link.
JS_ACHAR_ANDAMENTO = r"""
for (const a of document.querySelectorAll('a[href]')) {
  const h = a.getAttribute('href') || '';
  if (/acao=procedimento_consultar_(historico|andamento)/.test(h)) return a;
}
for (const img of document.querySelectorAll('img[title], img[alt]')) {
  const t = (img.title || img.alt || '');
  if (/consultar\s+andamento/i.test(t)) { const a = img.closest('a'); if (a) return a; }
}
for (const a of document.querySelectorAll('a')) {
  const t = (a.textContent || '') + ' ' + (a.title || '');
  if (/consultar\s+andamento/i.test(t)) return a;
}
return null;
"""

# "Ver histórico completo" na página de andamentos
JS_ACHAR_HIST_COMPLETO = r"""
for (const a of document.querySelectorAll('a[href]')) {
  if (/hist[oó]rico\s+completo/i.test(a.textContent || '')) return a;
}
return null;
"""

# Item "Visualizar/Abrir documento" do menu que o SEI abre ao clicar num nó.
# Alguns SEI, em vez de carregar o documento, abrem o menu do nó; este script
# acha o item de visualização desse menu (dá preferência ao que está dentro de
# um menu/popup visível) para que o duplo clique leve direto ao conteúdo.
JS_ACHAR_VER_DOC = r"""
function visivel(e){
  const r = e.getBoundingClientRect();
  return r.width > 0 && r.height > 0 && getComputedStyle(e).visibility !== 'hidden';
}
const acoes = /acao=(documento_visualizar|arvore_visualizar|procedimento_visualizar|protocolo_visualizar)/;
for (const m of document.querySelectorAll('[id*="enu" i],[class*="enu" i],[id*="opup" i],[class*="opup" i]')) {
  if (!visivel(m)) continue;
  for (const a of m.querySelectorAll('a[href]')) {
    const h = a.getAttribute('href') || '';
    if ((acoes.test(h) || /^\s*(visualizar|abrir|consultar\s+documento)\s*$/i.test(a.textContent || ''))
        && visivel(a)) return a;
  }
}
for (const a of document.querySelectorAll('a[href]')) {
  if (acoes.test(a.getAttribute('href') || '') && visivel(a)) return a;
}
return null;
"""

# Item da árvore pelo id (âncora do nó)
JS_ACHAR_ITEM = r"""
const id = arguments[0];
return document.getElementById('anchor' + id) ||
       (document.getElementById('span' + id) && document.getElementById('span' + id).closest('a')) ||
       document.getElementById('span' + id);
"""


def _mensagem_curta(erro):
    """Mensagem de erro do Selenium sem o stacktrace do chromedriver."""
    nome = type(erro).__name__
    texto = (getattr(erro, "msg", None) or str(erro) or "").strip()
    texto = texto.split("Stacktrace:")[0].strip()
    texto = " ".join(texto.split())[:400]
    if nome == "NoSuchWindowException":
        return ("A aba do navegador controlada pelo programa foi fechada ou trocada.\n"
                "Deixe a janela do navegador aberta e tente de novo.\n\n" + texto)
    return f"{nome}: {texto}"


def _acao(url):
    try:
        return parse_qs(urlsplit(url).query).get("acao", [""])[0]
    except ValueError:
        return ""


# ==========================================================
# CLIENTE SELENIUM (somente leitura)
# ==========================================================

class SeiSelenium:
    """Controla um Chrome/Edge pelo Selenium e lê as páginas do SEI."""

    def __init__(self):
        self.driver = None
        self.anexado = False          # True quando conectado a um navegador já aberto
        self.aba_login = None
        self.aba_trabalho = None
        self.url_controle = None
        self.trava = threading.RLock()

    # -- conexão -----------------------------------------------------------

    @staticmethod
    def _modulos():
        try:
            from selenium import webdriver
            from selenium.webdriver.common.by import By
            from selenium.webdriver.support.ui import WebDriverWait
            from selenium.common.exceptions import WebDriverException
            return webdriver, By, WebDriverWait, WebDriverException
        except ImportError:
            raise ErroSei("O módulo selenium não está instalado.\n\n"
                          "Instale com:  python -m pip install selenium")

    @staticmethod
    def pasta_perfil(navegador):
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return os.path.join(base, "SCyberPM", f"sei_perfil_{navegador.lower()}")

    def abrir(self, navegador, endereco):
        """Inicia um navegador controlado, com perfil próprio, no endereço."""
        webdriver, _, _, WebDriverException = self._modulos()
        with self.trava:
            self.fechar()
            edge = navegador.lower() == "edge"
            opcoes = webdriver.EdgeOptions() if edge else webdriver.ChromeOptions()
            opcoes.add_argument(f"--user-data-dir={self.pasta_perfil(navegador)}")
            opcoes.add_argument("--no-first-run")
            opcoes.add_argument("--no-default-browser-check")
            try:
                self.driver = webdriver.Edge(options=opcoes) if edge \
                    else webdriver.Chrome(options=opcoes)
            except WebDriverException as erro:
                self.driver = None
                raise ErroSei(f"Não foi possível iniciar o {navegador}.\n"
                              "Feche outras janelas que usem o mesmo perfil do S-Cyber PM "
                              f"e tente de novo.\n\n{erro.msg or erro}")
            self.anexado = False
            self.driver.set_page_load_timeout(60)
            time.sleep(1.5)                  # o Chrome pode trocar a aba inicial
            self._recuperar_janela()
            self.driver.get(endereco)

    def login(self, navegador, endereco, usuario, senha, orgao=None, ao_aguardar=None):
        """Abre o navegador (se preciso), preenche o login do SEI e entra.

        A senha só é digitada no campo da página; não é guardada. Se a página
        tiver captcha ou pedir um código (2 fatores), o programa espera você
        concluir na janela do navegador (ao_aguardar(msg) avisa a interface).
        """
        _, By, _, _ = self._modulos()
        if not usuario or not senha:
            raise ErroSei("Informe usuário e senha.")
        with self.trava:
            if not self.ativo:
                self.abrir(navegador, endereco)
            d = self.driver
            self._recuperar_janela()
            if not self._na_pagina_login():
                d.get(endereco)
            if not self._na_pagina_login():
                if self._logado_agora():
                    self.url_controle = self._achar_url_controle()
                    return "Já havia uma sessão aberta no SEI."
                self._esperar(lambda d: self._na_pagina_login(),
                              "Não encontrei o formulário de login. Confira o endereço.")

            campo_senha = self._campo_senha()
            campo_usuario = self._campo_usuario(campo_senha)
            if campo_usuario is None or campo_senha is None:
                raise ErroSei("A página de login não tem os campos esperados "
                              "(usuário/senha).")
            self._digitar(campo_usuario, usuario)
            self._digitar(campo_senha, senha)
            if orgao:
                self._escolher_orgao(orgao)

            if self._tem_captcha():
                if ao_aguardar:
                    ao_aguardar("A página tem captcha: resolva-o e clique em Acessar na "
                                "janela do navegador. Aguardando...")
            else:
                self._enviar_login(campo_senha)

            # Espera sair da página de login (inclui tempo para captcha/2FA manual)
            inicio = time.monotonic()
            avisou_2fa = False
            while True:
                try:
                    self._recuperar_janela()
                    erro = self._erro_login()
                    if erro:
                        raise ErroSei(erro)
                    if self._logado_agora() or self._procurar_aba_logada():
                        break
                except ErroSei:
                    raise
                except Exception:
                    pass                     # aba trocando durante o login: tenta de novo
                passou = time.monotonic() - inicio
                if passou > TEMPO_LOGIN:
                    raise ErroSei("O login não foi concluído a tempo.")
                if (not avisou_2fa and passou > 6 and not self._na_pagina_login()
                        and ao_aguardar):
                    avisou_2fa = True
                    ao_aguardar("O SEI pediu uma etapa extra (código/confirmação). Conclua na "
                                "janela do navegador. Aguardando...")
                time.sleep(0.5)
            self.url_controle = None
            self.url_controle = self._achar_url_controle()
            return "Login efetuado."

    # -- apoio ao login ----------------------------------------------------

    @staticmethod
    def _visivel(elementos):
        for e in elementos:
            try:
                if e.is_displayed() and e.is_enabled():
                    return e
            except Exception:
                continue
        return None

    def _na_pagina_login(self):
        _, By, _, _ = self._modulos()
        try:
            return self._campo_senha() is not None
        except Exception:
            return False

    # Seletores do campo de senha. O SEI-GO troca o type="password" por
    # type="text" com a classe "masked" (e remove o name) logo ao carregar.
    SELETORES_SENHA = ("input[type=password]", "#pwdSenha", "input.masked",
                       "input[id*='senha' i]", "input[name*='senha' i]")

    def _campo_senha(self):
        _, By, _, _ = self._modulos()
        for seletor in self.SELETORES_SENHA:
            e = self._visivel(self.driver.find_elements(By.CSS_SELECTOR, seletor))
            if e is not None:
                return e
        return None

    @staticmethod
    def _digitar(campo, texto):
        """Apaga e digita por eventos de teclado (o script de máscara da
        página só registra o que chega por teclas)."""
        from selenium.webdriver.common.keys import Keys
        campo.click()
        campo.send_keys(Keys.CONTROL, "a")
        campo.send_keys(Keys.DELETE)
        campo.send_keys(texto)

    def _logado_agora(self):
        try:
            url = self.driver.current_url
        except Exception:
            return False
        return ("controlador.php" in url and _acao(url) not in ("", "login")
                and not self._na_pagina_login())

    def _campo_usuario(self, campo_senha):
        _, By, _, _ = self._modulos()
        d = self.driver
        for seletor in ("#txtUsuario", "input[name*='usuario' i]", "input[id*='usuario' i]",
                        "input[name*='login' i]", "input[name*='user' i]",
                        "input[name*='cpf' i]", "input[id*='cpf' i]"):
            e = self._visivel(d.find_elements(By.CSS_SELECTOR, seletor))
            if e is not None and e != campo_senha:
                return e
        # Senão, o último campo de texto visível antes da senha
        if campo_senha is None:
            return None
        return d.execute_script(
            "const s=arguments[0]; let c=null;"
            "for (const i of document.querySelectorAll(\"input[type=text],input[type=email],"
            "input:not([type])\")) {"
            "  if (i.offsetParent && (i.compareDocumentPosition(s) & 4)) c=i; }"
            "return c;", campo_senha)

    def _escolher_orgao(self, orgao):
        from selenium.webdriver.support.ui import Select
        _, By, _, _ = self._modulos()
        alvo = orgao.strip().lower()
        for sel in self.driver.find_elements(By.TAG_NAME, "select"):
            try:
                if not sel.is_displayed():
                    continue
                lista = Select(sel)
                for op in lista.options:
                    texto = (op.text or "").strip().lower()
                    valor = (op.get_attribute("value") or "").strip().lower()
                    if texto == alvo or valor == alvo or alvo in texto:
                        lista.select_by_visible_text(op.text)
                        return
            except Exception:
                continue
        raise ErroSei(f"Órgão \"{orgao}\" não encontrado na lista da página de login.")

    def _tem_captcha(self):
        _, By, _, _ = self._modulos()
        d = self.driver
        seletores = ("iframe[src*='recaptcha']", "iframe[src*='hcaptcha']", ".g-recaptcha",
                     "input[name*='captcha' i]", "img[src*='captcha' i]")
        return any(self._visivel(d.find_elements(By.CSS_SELECTOR, s)) for s in seletores)

    def _enviar_login(self, campo_senha):
        _, By, _, _ = self._modulos()
        d = self.driver
        for seletor in ("#sbmLogin", "#sbmAcessar", "button[name*='acessar' i]",
                        "input[type=submit]", "button[type=submit]"):
            bt = self._visivel(d.find_elements(By.CSS_SELECTOR, seletor))
            if bt is not None:
                bt.click()
                return
        from selenium.webdriver.common.keys import Keys
        campo_senha.send_keys(Keys.ENTER)

    def _erro_login(self):
        """Mensagem de erro do login, se houver (alerta JS ou barra de erro)."""
        _, By, _, _ = self._modulos()
        d = self.driver
        try:
            alerta = d.switch_to.alert
            texto = alerta.text
            alerta.accept()
            return " ".join((texto or "Login recusado pelo SEI.").split())
        except Exception:
            pass
        if not self._na_pagina_login():
            return None
        for seletor in ("#divInfraBarraSistemaErro", ".infraBarraSistemaErro",
                        "#divInfraMsg", ".alert-danger", "#lblMensagem"):
            e = self._visivel(d.find_elements(By.CSS_SELECTOR, seletor))
            if e is not None and e.text.strip():
                return " ".join(e.text.split())
        return None

    def conectar(self, navegador, porta):
        """Liga-se a um Chrome/Edge aberto com --remote-debugging-port."""
        webdriver, _, _, WebDriverException = self._modulos()
        with self.trava:
            self.fechar()
            edge = navegador.lower() == "edge"
            opcoes = webdriver.EdgeOptions() if edge else webdriver.ChromeOptions()
            opcoes.debugger_address = f"127.0.0.1:{int(porta)}"
            try:
                self.driver = webdriver.Edge(options=opcoes) if edge \
                    else webdriver.Chrome(options=opcoes)
            except WebDriverException as erro:
                self.driver = None
                raise ErroSei(f"Não há {navegador} escutando na porta {porta}.\n\n"
                              "Abra o navegador assim (em uma pasta de perfil separada):\n"
                              f"  {'msedge' if edge else 'chrome'}.exe "
                              f"--remote-debugging-port={porta} --user-data-dir=C:\\SeiPerfil\n\n"
                              f"{erro.msg or erro}")
            self.anexado = True
            self.driver.set_page_load_timeout(60)
            self.aba_login = self.driver.current_window_handle

    @property
    def ativo(self):
        if self.driver is None:
            return False
        try:
            _ = self.driver.window_handles
            return True
        except Exception:
            return False

    def fechar(self):
        with self.trava:
            if self.driver is not None:
                try:
                    if self.anexado:
                        # Não fecha o navegador do usuário: só a aba de trabalho.
                        if self.aba_trabalho in self.driver.window_handles:
                            self.driver.switch_to.window(self.aba_trabalho)
                            self.driver.close()
                        self.driver.service.stop()
                    else:
                        self.driver.quit()
                except Exception:
                    pass
            self.driver = None
            self.aba_login = self.aba_trabalho = self.url_controle = None

    # -- utilidades --------------------------------------------------------

    def _exigir(self):
        if not self.ativo:
            raise ErroSei("O navegador não está aberto/conectado.")
        self._recuperar_janela()

    def _recuperar_janela(self):
        """Garante que o Selenium aponta para uma aba viva.

        O Chrome pode fechar/trocar a aba controlada (aba inicial do perfil,
        restauração de sessão, redirecionamento do login). Nesse caso passa
        para a aba do SEI que existir (ou a última aberta)."""
        d = self.driver
        try:
            handles = d.window_handles
        except Exception:
            raise ErroSei("O navegador foi fechado. Clique em \"Entrar no SEI\" de novo.")
        if not handles:
            raise ErroSei("O navegador não tem nenhuma aba aberta.")
        if self.aba_trabalho not in handles:
            self.aba_trabalho = None
        try:
            atual = d.current_window_handle
            if atual in handles:
                if self.aba_login not in handles:
                    self.aba_login = atual
                return atual
        except Exception:
            pass
        escolhida = None
        for h in handles:
            try:
                d.switch_to.window(h)
                if "sei" in (d.current_url or "").lower():
                    escolhida = h
                    if h != self.aba_trabalho:
                        break
            except Exception:
                continue
        escolhida = escolhida or handles[-1]
        d.switch_to.window(escolhida)
        d.switch_to.default_content()
        if self.aba_login not in handles:
            self.aba_login = escolhida
        return escolhida

    def _procurar_aba_logada(self):
        """Verifica se alguma aba já está logada no SEI (o login pode
        terminar em outra aba)."""
        d = self.driver
        atual = d.current_window_handle
        for h in d.window_handles:
            if h == atual:
                continue
            try:
                d.switch_to.window(h)
                if self._logado_agora():
                    self.aba_login = h
                    return True
            except Exception:
                continue
        try:
            d.switch_to.window(atual)
        except Exception:
            pass
        return False

    def _ir(self, url):
        """Navega na aba de trabalho, somente para ações de leitura."""
        acao = _acao(url)
        if acao not in ACOES_LEITURA:
            raise ErroSei(f"Ação \"{acao or '?'}\" não é de leitura; navegação recusada.")
        self._aba_trabalho()
        self.driver.get(url)
        self._checar_sessao()

    def _aba_trabalho(self):
        self._recuperar_janela()
        if not self.anexado:
            # Navegador aberto pelo programa: usa a mesma aba (não duplica a
            # tela do SEI). Só no navegador do usuário (Conectar) abre outra.
            self.aba_trabalho = self.driver.current_window_handle
        if self.aba_trabalho not in self.driver.window_handles:
            self.driver.switch_to.new_window("tab")
            self.aba_trabalho = self.driver.current_window_handle
        self.driver.switch_to.window(self.aba_trabalho)
        self.driver.switch_to.default_content()

    def _checar_sessao(self):
        d = self.driver
        texto = (d.page_source or "")[:200000]
        if re.search(r'type=["\']?password|id=["\']?pwdSenha', texto, re.I) and "controlador.php" not in d.current_url:
            raise ErroSei("O SEI pediu login de novo. Entre no SEI na janela do navegador.")
        if re.search(r"link sem assinatura|acesso negado", texto, re.I):
            raise ErroSei("O SEI recusou o link (sessão expirada ou link sem assinatura). "
                          "Atualize o Controle de Processos.")

    def _esperar(self, condicao, mensagem):
        _, _, WebDriverWait, _ = self._modulos()
        try:
            return WebDriverWait(self.driver, TEMPO_ESPERA).until(condicao)
        except Exception:
            raise ErroSei(mensagem)

    def _achar_url_controle(self):
        """Pega o link (assinado com infra_hash) do Controle de Processos em
        qualquer aba aberta no SEI."""
        d = self.driver
        for h in d.window_handles:
            try:
                d.switch_to.window(h)
                url = d.current_url
            except Exception:
                continue
            if _acao(url) == "procedimento_controlar":
                return url
            if "controlador.php" in url:
                try:
                    link = d.execute_script(
                        "const a=document.querySelector(\"a[href*='acao=procedimento_controlar']\");"
                        "return a ? a.href : null;")
                except Exception:
                    link = None
                if link:
                    return link
        return None

    # -- leitura -----------------------------------------------------------

    def controle_processos(self):
        with self.trava:
            self._exigir()
            url = self.url_controle or self._achar_url_controle()
            if not url:
                raise ErroSei("Não encontrei o SEI logado no navegador.\n"
                              "Faça o login na janela aberta e tente de novo.")
            self._ir(url)
            self.url_controle = self.driver.current_url
            self._esperar(lambda d: d.execute_script("return document.readyState") == "complete",
                          "O Controle de Processos não carregou a tempo.")
            return self.driver.execute_script(JS_CONTROLE) or []

    def pesquisar(self, termo):
        _, By, _, _ = self._modulos()
        with self.trava:
            self._exigir()
            if not self.url_controle:
                self.controle_processos()
            self._ir(self.url_controle)
            campos = self.driver.find_elements(By.ID, "txtPesquisaRapida")
            if not campos:
                raise ErroSei("Campo de pesquisa rápida não encontrado nesta versão do SEI.")
            antes = self.driver.current_url
            self.driver.execute_script(
                "const c=arguments[0]; c.value=arguments[1];"
                "const f=c.form||document.getElementById('frmProtocoloPesquisaRapida');"
                "if(!f) throw new Error('sem formulario');"
                "if(_acaoOk(f.action)) f.submit(); else throw new Error('acao recusada');"
                "function _acaoOk(u){return /acao=protocolo_pesquisa_rapida/.test(u||'');}",
                campos[0], termo)
            self._esperar(lambda d: d.current_url != antes and
                          d.execute_script("return document.readyState") == "complete",
                          "A pesquisa não respondeu a tempo.")
            self._checar_sessao()
            url = self.driver.current_url
            if _acao(url) in ("procedimento_trabalhar", "procedimento_visualizar"):
                # Pesquisa por número exato: o SEI abre o processo direto.
                return [{"numero": termo, "href": url, "secao": "Pesquisa", "tipo": "",
                         "especificacao": "", "atribuicao": "", "marcadores": "",
                         "nao_visualizado": False}]
            procs = self.driver.execute_script(JS_CONTROLE) or []
            for p in procs:
                p["secao"] = "Pesquisa"
            return procs

    # -- quadros (iframes) -------------------------------------------------
    #
    # No SEI, a árvore fica no quadro "ifrArvore" e o que se escolhe nela
    # (documento, andamentos) abre no quadro "ifrVisualizacao" - às vezes
    # dentro de "ifrConteudoVisualizacao" e, para documentos HTML, ainda em
    # "ifrArvoreHtml". Essas páginas não funcionam abertas sozinhas, por isso
    # o programa clica no item da árvore (só itens de visualização) e lê o
    # quadro onde o conteúdo apareceu.

    def _percorrer(self, func, caminho=()):
        """Chama func(caminho) no documento atual e em todos os quadros
        internos. Devolve [(caminho, resultado)]."""
        _, By, _, _ = self._modulos()
        d = self.driver
        try:
            res = [(caminho, func(caminho))]
        except Exception:
            res = [(caminho, None)]
        try:
            quadros = d.find_elements(By.CSS_SELECTOR, "iframe, frame")
        except Exception:
            quadros = []
        for i, q in enumerate(quadros):
            try:
                nome = q.get_attribute("id") or q.get_attribute("name") or f"quadro{i}"
                d.switch_to.frame(q)
            except Exception:
                continue
            try:
                res += self._percorrer(func, caminho + (nome,))
            finally:
                d.switch_to.parent_frame()
        return res

    def _ir_quadro(self, caminho):
        _, By, _, _ = self._modulos()
        d = self.driver
        d.switch_to.default_content()
        for nome in caminho:
            alvo = None
            for q in d.find_elements(By.CSS_SELECTOR, "iframe, frame"):
                if nome in (q.get_attribute("id"), q.get_attribute("name")):
                    alvo = q
                    break
            if alvo is None:
                quadros = d.find_elements(By.CSS_SELECTOR, "iframe, frame")
                m = re.fullmatch(r"quadro(\d+)", nome)
                if not m or int(m.group(1)) >= len(quadros):
                    raise ErroSei(f"Quadro \"{nome}\" não encontrado.")
                alvo = quadros[int(m.group(1))]
            d.switch_to.frame(alvo)

    def _marcar_quadros(self):
        """Marca os documentos atuais; os que forem recarregados perdem a
        marca, o que permite saber onde o novo conteúdo apareceu."""
        self.driver.switch_to.default_content()
        self._percorrer(lambda c: self.driver.execute_script("window.__scpm = 1;"))
        self.driver.switch_to.default_content()

    def _quadros_novos(self):
        """[(caminho, info)] dos quadros recarregados desde _marcar_quadros."""
        js = ("return {novo: window.__scpm === undefined, pronto: document.readyState,"
              " url: location.href, texto: document.body ? document.body.innerText : ''};")
        self.driver.switch_to.default_content()
        res = self._percorrer(lambda c: self.driver.execute_script(js))
        self.driver.switch_to.default_content()
        return [(c, i) for c, i in res
                if c and i and i.get("novo") and "ifrArvore" not in c]

    def _na_pagina_processo(self, href_proc):
        _, By, _, _ = self._modulos()
        d = self.driver
        d.switch_to.default_content()
        id_proc = lambda u: parse_qs(urlsplit(u).query).get("id_procedimento", [""])[0]
        if d.find_elements(By.ID, "ifrArvore") and id_proc(d.current_url) == id_proc(href_proc):
            return
        self._ir(href_proc)
        self._esperar(lambda d: d.find_elements(By.ID, "ifrArvore"),
                      "A árvore do processo não apareceu (layout diferente?).")

    def _clicar_na_arvore(self, js_achar, *args):
        """Executa js_achar no quadro da árvore; ele deve devolver o elemento
        a clicar (ou null). Confere se o link é de leitura antes de clicar."""
        _, By, _, _ = self._modulos()
        d = self.driver
        d.switch_to.default_content()
        d.switch_to.frame(d.find_element(By.ID, "ifrArvore"))
        try:
            el = d.execute_script(js_achar, *args)
            if el is None:
                return False
            href = el.get_attribute("href") or ""
            if href and not href.startswith("javascript") and not href.endswith("#") \
                    and _acao(href) not in ACOES_LEITURA:
                raise ErroSei(f"Link \"{_acao(href)}\" não é de leitura; clique recusado.")
            d.execute_script("arguments[0].scrollIntoView({block:'center'}); arguments[0].click();",
                             el)
            return True
        finally:
            d.switch_to.default_content()

    def _procurar_em_quadros(self, func, caminho=()):
        """Chama func(caminho) no documento atual e, se não resolver, em cada
        quadro interno. Para no primeiro resultado não-None."""
        _, By, _, _ = self._modulos()
        d = self.driver
        try:
            r = func(caminho)
        except Exception:
            r = None
        if r is not None:
            return r
        try:
            quadros = d.find_elements(By.CSS_SELECTOR, "iframe, frame")
        except Exception:
            quadros = []
        for i, q in enumerate(quadros):
            try:
                nome = q.get_attribute("id") or q.get_attribute("name") or f"quadro{i}"
                d.switch_to.frame(q)
            except Exception:
                continue
            try:
                r = self._procurar_em_quadros(func, caminho + (nome,))
            finally:
                d.switch_to.parent_frame()
            if r is not None:
                return r
        return None

    def _clicar_link_em_quadros(self, js_achar, *args):
        """Procura o elemento (js_achar) no documento e em qualquer quadro; ao
        achar um link de leitura, clica e devolve o caminho do quadro, senão None."""
        d = self.driver

        def tentar(caminho):
            try:
                el = d.execute_script(js_achar, *args)
            except Exception:
                el = None
            if el is None:
                return None
            try:
                href = el.get_attribute("href") or ""
            except Exception:
                href = ""
            if href and not href.startswith("javascript") and not href.endswith("#") \
                    and _acao(href) not in ACOES_LEITURA:
                return None                  # link de ação que não é leitura: ignora
            try:
                d.execute_script("arguments[0].scrollIntoView({block:'center'});"
                                 " arguments[0].click();", el)
                return caminho
            except Exception:
                return None

        d.switch_to.default_content()
        try:
            return self._procurar_em_quadros(tentar)
        finally:
            d.switch_to.default_content()

    def _clicar_raiz_arvore(self):
        """Clica no nó raiz (o próprio processo) na árvore, o que faz o SEI
        abrir a barra de ferramentas do processo no quadro de visualização."""
        _, By, _, _ = self._modulos()
        d = self.driver
        d.switch_to.default_content()
        try:
            d.switch_to.frame(d.find_element(By.ID, "ifrArvore"))
        except Exception:
            return False
        try:
            return bool(d.execute_script(
                "const a=document.querySelector(\"a[id^='anchor']\");"
                "if(!a){return false;}"
                "a.scrollIntoView({block:'center'}); a.click(); return true;"))
        except Exception:
            return False
        finally:
            d.switch_to.default_content()

    def _esperar_conteudo(self, aceitar, tempo=TEMPO_ESPERA):
        """Espera um quadro novo satisfazer aceitar(info). Devolve
        (caminho, info) ou o melhor candidato ao fim do tempo."""
        limite = time.monotonic() + tempo
        melhor = None
        while time.monotonic() < limite:
            novos = self._quadros_novos()
            for c, info in novos:
                if info.get("pronto") == "complete" and aceitar(c, info):
                    return c, info
            prontos = [x for x in novos if x[1].get("pronto") == "complete"]
            if prontos:
                melhor = max(prontos, key=lambda x: len(x[1].get("texto") or ""))
            time.sleep(0.5)
        return melhor

    # -- análise -----------------------------------------------------------

    def analisar(self, href):
        """Lê a árvore de documentos e os andamentos de um processo."""
        _, By, _, _ = self._modulos()
        with self.trava:
            self._exigir()
            self._ir(href)
            d = self.driver
            self._esperar(lambda d: d.find_elements(By.ID, "ifrArvore"),
                          "A árvore do processo não apareceu (layout diferente?).")
            d.switch_to.frame(d.find_element(By.ID, "ifrArvore"))
            self._esperar(lambda d: d.execute_script(
                "return document.querySelectorAll(\"a[id^='anchor']\").length") > 0,
                "A árvore do processo não carregou a tempo.")
            arvore = d.execute_script(JS_ARVORE) or {}
            d.switch_to.default_content()
            itens = arvore.get("itens", [])
            if itens:                        # a raiz (o processo) fica no nível 0
                menor = min(i.get("nivel", 0) for i in itens)
                for i in itens:
                    i["nivel"] = i.get("nivel", 0) - menor
            andamentos, aviso = self._ler_andamentos()
            return {"itens": itens, "andamentos": andamentos, "url": href,
                    "andamento_disponivel": aviso is None, "aviso_andamento": aviso}

    def _ler_andamentos(self):
        """Clica em "Consultar Andamento" na árvore e lê a tabela; se houver
        "Ver histórico completo", abre e lê também. Devolve (linhas, aviso)."""
        self._marcar_quadros()
        cam = self._clicar_link_em_quadros(JS_ACHAR_ANDAMENTO)
        if cam is None:
            # SEI 4.x: o link fica na barra do processo, que aparece ao abrir o
            # nó raiz da árvore. Abre a barra e procura de novo em todos os quadros.
            self._marcar_quadros()
            if self._clicar_raiz_arvore():
                self._esperar_conteudo(lambda c, i: True, 10)
                self._marcar_quadros()
                cam = self._clicar_link_em_quadros(JS_ACHAR_ANDAMENTO)
        if cam is None:
            return [], ("link \"Consultar Andamento\" não encontrado. Abra o processo e "
                        "confira se a barra de ferramentas do processo aparece.")
        achou = self._esperar_conteudo(lambda c, i: bool(self._historico_em(c)))
        if not achou:
            return [], "a página de andamentos não carregou."
        caminho = achou[0]
        linhas = self._historico_em(caminho)
        if not linhas:
            return [], "a página de andamentos não trouxe uma tabela reconhecível."
        # "Ver histórico completo" (mesma página, só exibe mais linhas)
        try:
            self._ir_quadro(caminho)
            el = self.driver.execute_script(JS_ACHAR_HIST_COMPLETO)
            if el is not None and _acao(el.get_attribute("href") or "") in ACOES_LEITURA:
                self._marcar_quadros()
                self._ir_quadro(caminho)
                self.driver.execute_script("arguments[0].click();", el)
                novo = self._esperar_conteudo(lambda c, i: bool(self._historico_em(c)), 15)
                if novo:
                    completas = self._historico_em(novo[0])
                    if len(completas) > len(linhas):
                        linhas = completas
        except Exception:
            pass
        finally:
            self.driver.switch_to.default_content()
        return linhas, None

    def _historico_em(self, caminho):
        try:
            self._ir_quadro(caminho)
            return self.driver.execute_script(JS_HISTORICO) or []
        except Exception:
            return []
        finally:
            self.driver.switch_to.default_content()

    def ler_documento(self, href_proc, item):
        """Clica no documento na árvore do processo e lê o texto do quadro
        de visualização. Para PDFs/anexos informa que não há texto."""
        with self.trava:
            self._exigir()
            self._na_pagina_processo(href_proc)
            self._marcar_quadros()
            if not self._clicar_na_arvore(JS_ACHAR_ITEM, item["id"]):
                raise ErroSei("O item não foi encontrado na árvore do processo.")

            def bom(c, info):
                texto = (info.get("texto") or "").strip()
                if not texto:
                    return False
                url = info.get("url") or ""
                # o documento em si (não a moldura com os botões)
                return c[-1] == "ifrArvoreHtml" or "documento_visualizar" in url

            achou = self._esperar_conteudo(bom, 6)
            if not achou:
                # Alguns SEI, em vez de carregar o documento, abrem o menu do
                # nó; aqui seguimos até o item "Visualizar" desse menu. Se não
                # houver menu, apenas esperamos o carregamento (documento lento).
                self._marcar_quadros()
                self._clicar_link_em_quadros(JS_ACHAR_VER_DOC)
                achou = self._esperar_conteudo(bom)
            if not achou:
                return "(o documento não carregou no quadro de visualização)"
            caminho, info = achou
            texto = (info.get("texto") or "").strip()
            if not texto:
                return ("(sem texto legível - o documento parece ser PDF ou anexo; use "
                        "\"Mostrar no navegador\" para vê-lo)")
            return texto[:LIMITE_TEXTO_DOC]

    def diagnostico(self, pasta):
        """Salva o HTML da página atual e de todos os quadros (para ajustar
        os seletores a esta instalação do SEI). Devolve a lista de arquivos."""
        with self.trava:
            self._exigir()
            os.makedirs(pasta, exist_ok=True)
            d = self.driver
            d.switch_to.default_content()
            salvos = []

            def salvar(caminho):
                nome = re.sub(r"[^\w.-]", "_", "_".join(("topo",) + caminho))
                arq = os.path.join(pasta, f"{len(salvos):02d}_{nome}.html")
                html = d.execute_script("return document.documentElement.outerHTML")
                url = d.execute_script("return location.href")
                with open(arq, "w", encoding="utf-8") as f:
                    f.write(f"<!-- {url} -->\n{html}")
                salvos.append(arq)

            self._percorrer(salvar)
            d.switch_to.default_content()
            return salvos

    def mostrar(self, href):
        """Exibe a página na aba de trabalho do navegador controlado."""
        with self.trava:
            self._exigir()
            self._ir(href)


# ==========================================================
# FORMULÁRIO
# ==========================================================

class FormSei(tk.Toplevel):

    LARGURA, ALTURA = 1120, 780

    def __init__(self, parent):
        super().__init__(parent)
        self.title("S-Cyber PM - SEI (análise pelo navegador - somente leitura)")
        self.geometry(f"{self.LARGURA}x{self.ALTURA}")
        self.minsize(900, 640)
        centralizar(self, parent, self.LARGURA, self.ALTURA)

        self.sei = SeiSelenium()
        self.ocupado = False
        self.processos = {}          # iid -> dict
        self.documentos = {}         # iid -> dict
        self.analise = None
        self.proc_analisado = None
        self.pendente = None         # processo pedido enquanto outra leitura rodava
        self._agendado = None        # after() da análise automática

        self._criar_interface()
        self.bind("<Escape>", lambda e: self._fechar())
        self.protocol("WM_DELETE_WINDOW", self._fechar)

    # ------------------------------------------------------
    # Interface
    # ------------------------------------------------------

    def _criar_interface(self):
        topo = tk.Canvas(self, height=56, bg="#101010", highlightthickness=0, bd=0)
        topo.pack(fill="x")
        botao_fechar_cabecalho(self, self._fechar)
        t1 = topo.create_text(18, 28, text="S-Cyber ", fill="white",
                              font=("Arial", 18, "bold"), anchor="w")
        t2 = topo.create_text(topo.bbox(t1)[2], 28, text="PM", fill="#ff0000",
                              font=("Arial", 18, "bold"), anchor="w")
        topo.create_text(topo.bbox(t2)[2] + 16, 29, fill="#d0d0d0", font=("Arial", 11),
                         anchor="w", text="SEI - análise de processos (Selenium, somente leitura)")

        corpo = ttk.Frame(self, padding=10)
        corpo.pack(fill="both", expand=True)
        corpo.columnconfigure(0, weight=1)
        corpo.rowconfigure(2, weight=1)

        # Navegador
        acesso = ttk.LabelFrame(corpo, text="Navegador controlado", padding=8)
        acesso.grid(row=0, column=0, sticky="ew")
        acesso.columnconfigure(1, weight=1)
        ttk.Label(acesso, text="Endereço:").grid(row=0, column=0, sticky="w")
        self.endereco = tk.StringVar(value="https://sei.go.gov.br/sei/")
        ttk.Entry(acesso, textvariable=self.endereco).grid(row=0, column=1, sticky="ew", padx=6)
        ttk.Label(acesso, text="Navegador:").grid(row=0, column=2, sticky="e")
        self.navegador = tk.StringVar(value="Chrome")
        ttk.Combobox(acesso, textvariable=self.navegador, values=("Chrome", "Edge"),
                     state="readonly", width=8).grid(row=0, column=3, padx=6)
        self.bt_abrir_nav = ttk.Button(acesso, text="Abrir navegador", command=self.abrir_navegador)
        self.bt_abrir_nav.grid(row=0, column=4)
        ttk.Label(acesso, text="Porta:").grid(row=0, column=5, sticky="e", padx=(10, 0))
        self.porta = tk.StringVar(value="9222")
        ttk.Entry(acesso, textvariable=self.porta, width=6).grid(row=0, column=6, padx=4)
        self.bt_conectar = ttk.Button(acesso, text="Conectar", command=self.conectar)
        self.bt_conectar.grid(row=0, column=7)
        self.bt_desconectar = ttk.Button(acesso, text="Desconectar", command=self.desconectar,
                                         state="disabled")
        self.bt_desconectar.grid(row=0, column=8, padx=(6, 0))

        # Credenciais (o login é feito pelo Selenium na janela do navegador)
        cred = ttk.Frame(acesso)
        cred.grid(row=1, column=0, columnspan=9, sticky="ew", pady=(6, 0))
        ttk.Label(cred, text="Usuário:").pack(side="left")
        self.usuario = tk.StringVar()
        campo_usuario = ttk.Entry(cred, textvariable=self.usuario, width=22)
        campo_usuario.pack(side="left", padx=(6, 12))
        ttk.Label(cred, text="Senha:").pack(side="left")
        self.senha = tk.StringVar()
        self.campo_senha = ttk.Entry(cred, textvariable=self.senha, show="•", width=22)
        self.campo_senha.pack(side="left", padx=(6, 12))
        ttk.Label(cred, text="Órgão:").pack(side="left")
        self.orgao = tk.StringVar()
        campo_orgao = ttk.Entry(cred, textvariable=self.orgao, width=14)
        campo_orgao.pack(side="left", padx=(6, 12))
        self.bt_entrar = ttk.Button(cred, text="Entrar no SEI", command=self.entrar)
        self.bt_entrar.pack(side="left")
        ttk.Label(cred, foreground="#606060", font=("Segoe UI", 8),
                  text="  (órgão: opcional; captcha/código é concluído por você no navegador)"
                  ).pack(side="left")
        for campo in (campo_usuario, self.campo_senha, campo_orgao):
            campo.bind("<Return>", lambda e: self.entrar())

        # Ações
        acoes = ttk.Frame(corpo)
        acoes.grid(row=1, column=0, sticky="ew", pady=(8, 4))
        self.bt_controle = ttk.Button(acoes, text="Ler Controle de Processos",
                                      command=self.carregar_controle, state="disabled")
        self.bt_controle.pack(side="left")
        ttk.Label(acoes, text="   Pesquisar (número ou termo):").pack(side="left")
        self.busca = tk.StringVar()
        campo = ttk.Entry(acoes, textvariable=self.busca)
        campo.pack(side="left", fill="x", expand=True, padx=6)
        campo.bind("<Return>", lambda e: self.pesquisar())
        self.bt_pesquisar = ttk.Button(acoes, text="Pesquisar", command=self.pesquisar,
                                       state="disabled")
        self.bt_pesquisar.pack(side="left")
        ttk.Label(acoes, text="  Filtro:").pack(side="left")
        self.filtro = tk.StringVar()
        self.filtro.trace_add("write", lambda *a: self._aplicar_filtro())
        ttk.Entry(acoes, textvariable=self.filtro, width=18).pack(side="left", padx=4)

        # Painel dividido: lista de processos / análise
        painel = ttk.PanedWindow(corpo, orient="vertical")
        painel.grid(row=2, column=0, sticky="nsew")

        quadro = ttk.LabelFrame(painel, text="Processos", padding=4)
        colunas = ("secao", "tipo", "especificacao", "atribuicao", "marcadores")
        self.tabela = ttk.Treeview(quadro, columns=colunas, show="tree headings",
                                   selectmode="browse", height=9)
        self.tabela.heading("#0", text="Número", anchor="w")
        for col, txt, larg in (("secao", "Seção", 80), ("tipo", "Tipo", 220),
                               ("especificacao", "Especificação", 300),
                               ("atribuicao", "Atribuído", 90), ("marcadores", "Marcadores", 160)):
            self.tabela.heading(col, text=txt, anchor="w",
                                command=lambda c=col: self._ordenar(c))
            self.tabela.column(col, width=larg, stretch=col == "especificacao")
        self.tabela.column("#0", width=200, stretch=False)
        self.tabela.tag_configure("naovisto", foreground="#c00000")
        sy = ttk.Scrollbar(quadro, orient="vertical", command=self.tabela.yview)
        self.tabela.configure(yscrollcommand=sy.set)
        self.tabela.pack(side="left", fill="both", expand=True)
        sy.pack(side="right", fill="y")
        self.tabela.bind("<Double-1>", lambda e: self.analisar())
        self.tabela.bind("<<TreeviewSelect>>", lambda e: self._ao_selecionar())
        painel.add(quadro, weight=2)

        analise = ttk.LabelFrame(painel, text="Análise do processo", padding=4)
        self.quadro_analise = analise
        self.abas = ttk.Notebook(analise)
        self.abas.pack(fill="both", expand=True)

        self.txt_resumo = self._caixa_texto(self.abas)
        self.abas.add(self.txt_resumo.master, text="Resumo")

        f_docs = ttk.Frame(self.abas)
        self.arv_docs = ttk.Treeview(f_docs, columns=("titulo",), show="tree headings")
        self.arv_docs.heading("#0", text="Documento", anchor="w")
        self.arv_docs.heading("titulo", text="Dica / tipo", anchor="w")
        self.arv_docs.column("#0", width=520)
        self.arv_docs.column("titulo", width=380)
        sd = ttk.Scrollbar(f_docs, orient="vertical", command=self.arv_docs.yview)
        self.arv_docs.configure(yscrollcommand=sd.set)
        self.arv_docs.pack(side="left", fill="both", expand=True)
        sd.pack(side="right", fill="y")
        self.arv_docs.bind("<Double-1>", lambda e: self.ler_documento())
        self.abas.add(f_docs, text="Documentos")

        f_and = ttk.Frame(self.abas)
        self.tab_and = ttk.Treeview(f_and, columns=("data", "unidade", "usuario", "descricao"),
                                    show="headings")
        for col, txt, larg in (("data", "Data/Hora", 130), ("unidade", "Unidade", 140),
                               ("usuario", "Usuário", 140), ("descricao", "Descrição", 520)):
            self.tab_and.heading(col, text=txt, anchor="w")
            self.tab_and.column(col, width=larg, stretch=col == "descricao")
        sa = ttk.Scrollbar(f_and, orient="vertical", command=self.tab_and.yview)
        self.tab_and.configure(yscrollcommand=sa.set)
        self.tab_and.pack(side="left", fill="both", expand=True)
        sa.pack(side="right", fill="y")
        self.abas.add(f_and, text="Andamentos")

        self.txt_doc = self._caixa_texto(self.abas)
        self.abas.add(self.txt_doc.master, text="Conteúdo do documento")
        painel.add(analise, weight=3)

        # Rodapé
        rodape = ttk.Frame(corpo)
        rodape.grid(row=3, column=0, sticky="ew", pady=(6, 0))
        self.status = ttk.Label(rodape, foreground="#505050",
                                text="Abra o navegador, faça o login no SEI e leia o Controle "
                                     "de Processos.")
        self.status.pack(side="left")
        self.progresso = ttk.Progressbar(rodape, mode="indeterminate", length=120)
        self.bt_exportar = ttk.Button(rodape, text="Exportar análise...", command=self.exportar,
                                      state="disabled")
        self.bt_exportar.pack(side="right", padx=6)
        self.bt_mostrar = ttk.Button(rodape, text="Mostrar no navegador", command=self.mostrar,
                                     state="disabled")
        self.bt_mostrar.pack(side="right")
        self.bt_analisar = ttk.Button(rodape, text="Analisar processo", command=self.analisar,
                                      state="disabled")
        self.bt_analisar.pack(side="right", padx=6)
        self.bt_diag = ttk.Button(rodape, text="Diagnóstico...", command=self.diagnostico,
                                  state="disabled")
        self.bt_diag.pack(side="right")

        ttk.Label(corpo, foreground="#606060", wraplength=1080, justify="left",
                  font=("Segoe UI", 8),
                  text=("Somente leitura: o programa não clica em botões do SEI e só abre páginas "
                        "de consulta. A senha é usada só para o login e não é gravada. Abrir um "
                        "processo não visualizado (em vermelho) o marca como visualizado na "
                        "unidade, como acontece ao abri-lo manualmente.")
                  ).grid(row=4, column=0, sticky="w", pady=(4, 0))

    @staticmethod
    def _caixa_texto(pai):
        f = ttk.Frame(pai)
        t = tk.Text(f, wrap="word", font=("Consolas", 10), state="disabled")
        s = ttk.Scrollbar(f, orient="vertical", command=t.yview)
        t.configure(yscrollcommand=s.set)
        t.pack(side="left", fill="both", expand=True)
        s.pack(side="right", fill="y")
        return t

    @staticmethod
    def _escrever(caixa, texto):
        caixa.configure(state="normal")
        caixa.delete("1.0", "end")
        caixa.insert("1.0", texto)
        caixa.configure(state="disabled")

    # ------------------------------------------------------
    # Estado / tarefas em segundo plano
    # ------------------------------------------------------

    def _ui(self, func, *args):
        try:
            if self.winfo_exists():
                self.after(0, func, *args)
        except tk.TclError:
            pass

    def _ocupar(self, sim, texto=None):
        self.ocupado = sim
        if texto:
            self.status.configure(text=texto)
        if sim:
            self.progresso.pack(side="right", padx=8)
            self.progresso.start(12)
        else:
            self.progresso.stop()
            self.progresso.pack_forget()

    def _executar(self, texto, trabalho, ao_terminar):
        """Roda trabalho() numa thread; ao_terminar(resultado) volta na interface."""
        if self.ocupado:
            return
        self._ocupar(True, texto)

        def tarefa():
            for tentativa in (1, 2):
                try:
                    res = trabalho()
                    self._ui(self._fim_ok, ao_terminar, res)
                    return
                except ErroSei as erro:
                    self._ui(self._fim_erro, str(erro))
                    return
                except Exception as erro:         # falhas do navegador
                    nome = type(erro).__name__
                    if nome in ("NoSuchWindowException", "NoSuchFrameException",
                                "StaleElementReferenceException") and tentativa == 1:
                        try:
                            self.sei._recuperar_janela()
                            continue              # a aba mudou: tenta mais uma vez
                        except Exception:
                            pass
                    self._ui(self._fim_erro, _mensagem_curta(erro))
                    return

        threading.Thread(target=tarefa, daemon=True).start()

    def _fim_ok(self, ao_terminar, res):
        self._ocupar(False)
        ao_terminar(res)
        self._proximo()

    def _fim_erro(self, msg):
        self._ocupar(False, "Falha na operação.")
        if not self.sei.ativo:
            self._habilitar(False)
            self.pendente = None
        messagebox.showerror("SEI", msg, parent=self)
        self._proximo()

    def _proximo(self):
        """Roda a análise pedida enquanto outra leitura estava em andamento,
        se o processo ainda for o selecionado."""
        proc, self.pendente = self.pendente, None
        if proc is not None and proc is self._proc_da_selecao() \
                and proc is not self.proc_analisado:
            self._analisar_proc(proc)

    def _habilitar(self, conectado):
        estado = ["!disabled"] if conectado else ["disabled"]
        for bt in (self.bt_desconectar, self.bt_controle, self.bt_pesquisar,
                   self.bt_analisar, self.bt_mostrar, self.bt_diag):
            bt.state(estado)
        for bt in (self.bt_abrir_nav, self.bt_conectar):
            bt.state(["disabled"] if conectado else ["!disabled"])

    # ------------------------------------------------------
    # Navegador
    # ------------------------------------------------------

    def abrir_navegador(self):
        endereco = self.endereco.get().strip()
        if not endereco.lower().startswith("https://"):
            messagebox.showinfo("SEI", "Use um endereço HTTPS do SEI.", parent=self)
            return
        nav = self.navegador.get()
        self._executar(f"Abrindo o {nav}...", lambda: self.sei.abrir(nav, endereco),
                       lambda _: self._conectado(
                           f"{nav} aberto. Faça o login no SEI nessa janela e depois clique em "
                           "\"Ler Controle de Processos\"."))

    def entrar(self):
        """Faz o login no SEI pelo Selenium com as credenciais desta janela."""
        if self.ocupado:
            return
        endereco = self.endereco.get().strip()
        usuario = self.usuario.get().strip()
        senha = self.senha.get()
        orgao = self.orgao.get().strip() or None
        if not endereco.lower().startswith("https://"):
            messagebox.showinfo("SEI", "Use um endereço HTTPS do SEI.", parent=self)
            return
        if not usuario or not senha:
            messagebox.showinfo("SEI", "Informe o usuário e a senha.", parent=self)
            return
        self.senha.set("")                   # não deixa a senha retida no campo
        nav = self.navegador.get()
        aviso = lambda msg: self._ui(self.status.configure, {"text": msg})

        def trabalho():
            msg = self.sei.login(nav, endereco, usuario, senha, orgao, ao_aguardar=aviso)
            return msg, self.sei.controle_processos()

        def terminou(res):
            msg, procs = res
            self._conectado(f"{msg} Usuário: {usuario}.")
            self._mostrar(procs, "Controle de Processos")

        self._executar(f"Entrando no SEI como {usuario}...", trabalho, terminou)

    def conectar(self):
        try:
            porta = int(self.porta.get())
        except ValueError:
            messagebox.showinfo("SEI", "Porta inválida.", parent=self)
            return
        nav = self.navegador.get()
        self._executar(f"Conectando ao {nav} na porta {porta}...",
                       lambda: self.sei.conectar(nav, porta),
                       lambda _: self._conectado(f"Conectado ao {nav} (porta {porta})."))

    def _conectado(self, msg):
        self._habilitar(True)
        self.status.configure(text=msg)

    def desconectar(self):
        if self.ocupado:
            return
        self.sei.fechar()
        self._habilitar(False)
        self.status.configure(text="Navegador desconectado.")

    # ------------------------------------------------------
    # Lista de processos
    # ------------------------------------------------------

    def carregar_controle(self):
        self._executar("Lendo o Controle de Processos...", self.sei.controle_processos,
                       lambda procs: self._mostrar(procs, "Controle de Processos"))

    def pesquisar(self):
        termo = self.busca.get().strip()
        if not termo or not self.sei.ativo:
            return
        self._executar(f"Pesquisando \"{termo}\"...", lambda: self.sei.pesquisar(termo),
                       lambda procs: self._mostrar(procs, f"Pesquisa por \"{termo}\""))

    def _mostrar(self, procs, titulo):
        self.lista = procs
        self._aplicar_filtro()
        nv = sum(1 for p in procs if p.get("nao_visualizado"))
        if procs:
            self.status.configure(text=f"{titulo}: {len(procs)} processo(s), {nv} não "
                                       "visualizado(s). Duplo clique para analisar.")
        else:
            self.status.configure(text=f"{titulo}: nenhum processo encontrado (ou o layout "
                                       "do SEI difere do esperado).")

    def _aplicar_filtro(self):
        procs = getattr(self, "lista", [])
        filtro = self.filtro.get().strip().lower()
        self.tabela.delete(*self.tabela.get_children())
        self.processos = {}
        for p in procs:
            linha = (p.get("secao", ""), p.get("tipo", ""), p.get("especificacao", ""),
                     p.get("atribuicao", ""), p.get("marcadores", ""))
            if filtro and filtro not in (p.get("numero", "") + " " + " ".join(linha)).lower():
                continue
            iid = self.tabela.insert("", "end", text=p.get("numero", "?"), values=linha,
                                     tags=("naovisto",) if p.get("nao_visualizado") else ())
            self.processos[iid] = p

    def _ordenar(self, coluna):
        itens = [(self.tabela.set(i, coluna).lower(), i) for i in self.tabela.get_children()]
        itens.sort()
        for pos, (_, i) in enumerate(itens):
            self.tabela.move(i, "", pos)

    def _selecionado(self):
        selec = self.tabela.selection()
        if not selec:
            messagebox.showinfo("SEI", "Selecione um processo na lista.", parent=self)
            return None
        return self.processos.get(selec[0])

    # ------------------------------------------------------
    # Análise
    # ------------------------------------------------------

    def _proc_da_selecao(self):
        selec = self.tabela.selection()
        return self.processos.get(selec[0]) if selec else None

    def _limpar_analise(self, titulo, aviso):
        """Esvazia as abas para não mostrar dados de outro processo."""
        self.analise = self.proc_analisado = None
        self.quadro_analise.configure(text=titulo)
        self.arv_docs.delete(*self.arv_docs.get_children())
        self.tab_and.delete(*self.tab_and.get_children())
        self.documentos = {}
        self._escrever(self.txt_resumo, aviso)
        self._escrever(self.txt_doc, "")
        self.bt_exportar.state(["disabled"])

    def _ao_selecionar(self):
        """Clique simples: troca a análise para o processo selecionado."""
        if self._agendado:
            self.after_cancel(self._agendado)
            self._agendado = None
        proc = self._proc_da_selecao()
        if proc is None or proc is self.proc_analisado or not self.sei.ativo:
            return
        if proc.get("nao_visualizado"):
            self.pendente = None
            self._limpar_analise(f"Análise do processo {proc['numero']}",
                                 f"{proc['numero']} ainda não foi visualizado na unidade.\n\n"
                                 "Dê duplo clique (ou \"Analisar processo\") para analisá-lo; "
                                 "o SEI passará a mostrá-lo como visualizado.")
            return
        self._limpar_analise(f"Análise do processo {proc['numero']}",
                             f"Analisando {proc['numero']}...")
        # pequeno intervalo: navegar com as setas não dispara uma leitura por linha
        self._agendado = self.after(400, lambda: self._analisar_proc(proc))

    def analisar(self):
        """Duplo clique / botão: analisa o selecionado (pede confirmação se
        ainda não foi visualizado)."""
        if not self.sei.ativo:
            return
        proc = self._selecionado()
        if not proc or proc is self.proc_analisado:
            return
        if proc.get("nao_visualizado") and not messagebox.askyesno(
                "SEI", f"O processo {proc['numero']} ainda não foi visualizado na unidade.\n\n"
                       "Ao abri-lo, o SEI passa a mostrá-lo como visualizado (como acontece "
                       "ao abrir manualmente). Continuar?", parent=self):
            return
        if self._agendado:
            self.after_cancel(self._agendado)
        self._analisar_proc(proc)

    def _analisar_proc(self, proc):
        self._agendado = None
        if proc is not self._proc_da_selecao():
            return
        self._limpar_analise(f"Análise do processo {proc['numero']}",
                             f"Analisando {proc['numero']}...")
        if self.ocupado:
            self.pendente = proc             # roda quando a leitura atual terminar
            self.status.configure(text=f"{proc['numero']} será analisado em seguida...")
            return
        self._executar(f"Analisando {proc['numero']}...", lambda: self.sei.analisar(proc["href"]),
                       lambda res: self._mostrar_analise(proc, res))

    def _mostrar_analise(self, proc, res):
        selecionado = self._proc_da_selecao()
        if selecionado is not None and selecionado is not proc:
            return                           # o usuário já escolheu outro processo
        proc["nao_visualizado"] = False
        self.quadro_analise.configure(text=f"Análise do processo {proc.get('numero', '')}")
        self.analise, self.proc_analisado = res, proc
        itens, andamentos = res["itens"], res["andamentos"]

        self.arv_docs.delete(*self.arv_docs.get_children())
        self.documentos = {}
        pais = {}
        for it in itens:
            nivel = it.get("nivel", 0)
            pai = pais.get(nivel - 1, "") if nivel > 0 else ""
            iid = self.arv_docs.insert(pai, "end", text=it["texto"],
                                       values=(it.get("titulo") or it.get("tipo", ""),), open=True)
            pais[nivel] = iid
            self.documentos[iid] = it

        self.tab_and.delete(*self.tab_and.get_children())
        for linha in andamentos:
            cols = (linha + ["", "", "", ""])[:4] if len(linha) < 4 else \
                [linha[0], linha[1], linha[2], " ".join(linha[3:])]
            self.tab_and.insert("", "end", values=cols)

        self._escrever(self.txt_resumo, self._texto_resumo(proc, res))
        self._escrever(self.txt_doc, "Duplo clique num documento da aba \"Documentos\" para "
                                     "ler o conteúdo.")
        self.abas.select(0)
        self.bt_exportar.state(["!disabled"])
        for iid, p in self.processos.items():
            if p is proc:
                self.tabela.item(iid, tags=())
        self.status.configure(text=f"{proc['numero']}: {max(len(itens) - 1, 0)} item(ns) na "
                                   f"árvore, {len(andamentos)} andamento(s).")

    def _texto_resumo(self, proc, res):
        itens, andamentos = res["itens"], res["andamentos"]
        docs = [i for i in itens if i.get("nivel", 0) > 0]
        linhas = [
            f"Processo .......: {proc.get('numero', '')}",
            f"Tipo ...........: {proc.get('tipo') or (itens[0].get('titulo') if itens else '')}",
            f"Especificação ..: {proc.get('especificacao', '')}",
            f"Seção ..........: {proc.get('secao', '')}",
            f"Atribuído a ....: {proc.get('atribuicao') or '-'}",
            f"Marcadores .....: {proc.get('marcadores') or '-'}",
            "",
            f"Itens na árvore : {len(docs)}",
        ]
        tipos = {}
        for d in docs:
            nome = re.sub(r"\s*\(?\d[\d./-]*\)?\s*$", "", d["texto"]).strip() or d["texto"]
            tipos[nome] = tipos.get(nome, 0) + 1
        for nome, qtd in sorted(tipos.items(), key=lambda x: (-x[1], x[0]))[:15]:
            linhas.append(f"   {qtd:>3} x {nome}")
        if docs:
            linhas += ["", f"Primeiro item ..: {docs[0]['texto']}",
                       f"Último item ....: {docs[-1]['texto']}"]
        linhas.append("")
        if andamentos:
            unidades = sorted({a[1] for a in andamentos if len(a) > 1 and a[1]})
            linhas += [f"Andamentos .....: {len(andamentos)}",
                       f"Mais recente ...: {' | '.join(andamentos[0])}",
                       f"Mais antigo ....: {' | '.join(andamentos[-1])}",
                       f"Unidades .......: {', '.join(unidades)}"]
        else:
            linhas.append("Andamentos .....: " + (res.get("aviso_andamento") or
                                                  "nenhum andamento lido."))
        return "\n".join(linhas)

    def ler_documento(self):
        if self.ocupado or not self.sei.ativo:
            return
        selec = self.arv_docs.selection()
        if not selec:
            return
        doc = self.documentos.get(selec[0])
        if not doc or not self.proc_analisado:
            return
        href_proc = self.proc_analisado["href"]
        self._executar(f"Lendo \"{doc['texto']}\"...",
                       lambda: self.sei.ler_documento(href_proc, doc),
                       lambda txt: self._mostrar_doc(doc, txt))

    def _mostrar_doc(self, doc, texto):
        if not any(d is doc for d in self.documentos.values()):
            return                           # já trocou de processo
        self._escrever(self.txt_doc, f"{doc['texto']}\n{'=' * 80}\n\n{texto}")
        self.abas.select(3)
        self.status.configure(text=f"Documento lido: {doc['texto']} ({len(texto)} caracteres).")

    def mostrar(self):
        """Mostra o processo selecionado na aba de trabalho do navegador controlado."""
        proc = self._selecionado()
        if not proc:
            return
        self._executar(f"Abrindo {proc['numero']} no navegador...",
                       lambda: self.sei.mostrar(proc["href"]),
                       lambda _: self.status.configure(
                           text=f"{proc['numero']} aberto no navegador controlado."))

    def diagnostico(self):
        """Salva o HTML da página atual do navegador e de seus quadros."""
        pasta = filedialog.askdirectory(parent=self, title="Pasta para salvar o diagnóstico")
        if not pasta:
            return
        pasta = os.path.join(pasta, f"diagnostico_sei_{datetime.now():%Y%m%d_%H%M%S}")
        self._executar("Salvando o HTML da página e dos quadros...",
                       lambda: self.sei.diagnostico(pasta),
                       lambda arqs: messagebox.showinfo(
                           "SEI", f"{len(arqs)} arquivo(s) salvo(s) em:\n{pasta}\n\n"
                                  "Eles contêm dados dos processos: compartilhe só com "
                                  "quem pode vê-los.", parent=self))

    def exportar(self):
        if not self.analise or not self.proc_analisado:
            return
        proc = self.proc_analisado
        nome = re.sub(r"[^\w.-]", "_", proc.get("numero", "processo"))
        caminho = filedialog.asksaveasfilename(
            parent=self, title="Exportar análise", defaultextension=".txt",
            initialfile=f"analise_{nome}.txt", filetypes=[("Texto", "*.txt")])
        if not caminho:
            return
        partes = [f"Análise SEI - gerada em {datetime.now():%d/%m/%Y %H:%M}", "",
                  self._texto_resumo(proc, self.analise), "", "ÁRVORE DO PROCESSO", "-" * 60]
        for it in self.analise["itens"]:
            partes.append("  " * it.get("nivel", 0) + it["texto"])
        partes += ["", "ANDAMENTOS", "-" * 60]
        partes += [" | ".join(a) for a in self.analise["andamentos"]]
        with open(caminho, "w", encoding="utf-8") as arq:
            arq.write("\n".join(partes) + "\n")
        self.status.configure(text=f"Análise exportada para {caminho}")

    def _fechar(self):
        try:
            self.sei.fechar()
        except Exception:
            pass
        self.destroy()


# ==========================================================
# EXECUÇÃO DIRETA (teste)
# ==========================================================

def main():
    root = tk.Tk()
    root.withdraw()
    form = FormSei(root)
    form.bind("<Destroy>", lambda e: root.quit() if e.widget is form else None)
    root.mainloop()


if __name__ == "__main__":
    main()
