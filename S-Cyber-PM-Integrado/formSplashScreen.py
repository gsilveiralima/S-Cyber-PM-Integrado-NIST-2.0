# ==============================================================================
#  S-Cyber PM - Cryptography and Digital Certificate Framework
# ------------------------------------------------------------------------------
#  Arquivo     : formSplashScreen.py
#  Descrição   : Tela de abertura alternativa (protótipo)
#  Tipo        : Formulário (tkinter)
#  Versão      : ver formAbout.APP_VERSAO (fonte única da versão)
#  Revisão     : 2026-11-15
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
#    1.4     2026-11-15  Renomeado de splash_screen.py
#                        Cabeçalho padrão de identificação e revisão
# ==============================================================================
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from PIL import Image, ImageTk
import subprocess
import sys


# ==========================================================
# CONFIGURAÇÃO DO CERTIFICADO
# ==========================================================

CERT_SUBJECT = "S-Cyber PM"


# ==========================================================
# VERIFICAÇÃO DO CERTIFICADO
# ==========================================================

def validar_certificado():

    try:

        comando = f"""
        Get-ChildItem Cert:\\CurrentUser\\My |
        Where-Object {{
            $_.Subject -like '*{CERT_SUBJECT}*' -and
            $_.NotAfter -gt (Get-Date)
        }}
        """

        resultado = subprocess.run(
            ["powershell", "-Command", comando],
            capture_output=True,
            text=True,
            timeout=10
        )

        return bool(resultado.stdout.strip())

    except Exception:
        return False


# ==========================================================
# SPLASH SCREEN
# ==========================================================

class SplashScreen(tk.Toplevel):

    def __init__(self, parent):

        super().__init__(parent)

        self.parent = parent

        self.width = 1200
        self.height = 700

        self.progress_value = 0

        self.overrideredirect(True)

        self.center_window()

        self.create_interface()

        self.after(500, self.load_modules)

    # ======================================================
    # CENTRALIZAÇÃO
    # ======================================================

    def center_window(self):

        x = (self.winfo_screenwidth() // 2) - (self.width // 2)
        y = (self.winfo_screenheight() // 2) - (self.height // 2)

        self.geometry(
            f"{self.width}x{self.height}+{x}+{y}"
        )

    # ======================================================
    # INTERFACE
    # ======================================================

    def create_interface(self):

        # --------------------------------------------------
        # FUNDO
        # --------------------------------------------------

        image = Image.open("watermark.png")

        image = image.resize(
            (
                self.width,
                self.height
            )
        )

        self.bg = ImageTk.PhotoImage(image)

        self.background = tk.Label(
            self,
            image=self.bg
        )

        self.background.place(
            relwidth=1,
            relheight=1
        )

        # --------------------------------------------------
        # OVERLAY ESCURO
        # --------------------------------------------------

        self.overlay = tk.Frame(
            self,
            bg="#000000"
        )

        self.overlay.place(
            relwidth=1,
            relheight=1
        )

        self.overlay.tkraise()

        # --------------------------------------------------
        # TÍTULO
        # --------------------------------------------------

        frame_title = tk.Frame(
            self.overlay,
            bg="#000000"
        )

        frame_title.place(
            relx=0.5,
            rely=0.25,
            anchor="center"
        )

        tk.Label(
            frame_title,
            text="S-Cyber ",
            font=("Arial", 48, "bold"),
            fg="white",
            bg="#000000"
        ).pack(
            side="left"
        )

        tk.Label(
            frame_title,
            text="PM",
            font=("Arial", 48, "bold"),
            fg="#ff0000",
            bg="#000000"
        ).pack(
            side="left"
        )

        # --------------------------------------------------
        # SUBTÍTULO
        # --------------------------------------------------

        tk.Label(
            self.overlay,
            text="Cryptography and Digital Certificate Framework",
            font=("Arial", 18, "bold"),
            fg="white",
            bg="#000000"
        ).place(
            relx=0.5,
            rely=0.35,
            anchor="center"
        )

        tk.Label(
            self.overlay,
            text="Cyber Security • RSA • Digital Signatures • PKI",
            font=("Arial", 12),
            fg="#d0d0d0",
            bg="#000000"
        ).place(
            relx=0.5,
            rely=0.40,
            anchor="center"
        )

        # --------------------------------------------------
        # STATUS
        # --------------------------------------------------

        self.lbl_status = tk.Label(
            self.overlay,
            text="Initializing...",
            font=("Arial", 12, "bold"),
            fg="white",
            bg="#000000"
        )

        self.lbl_status.place(
            relx=0.5,
            rely=0.82,
            anchor="center"
        )

        # --------------------------------------------------
        # BARRA DE PROGRESSO
        # --------------------------------------------------

        style = ttk.Style()

        style.theme_use("clam")

        style.configure(
            "Red.Horizontal.TProgressbar",
            troughcolor="#202020",
            background="#d10000",
            darkcolor="#900000",
            lightcolor="#ff0000",
            thickness=18
        )

        self.progress = ttk.Progressbar(
            self.overlay,
            style="Red.Horizontal.TProgressbar",
            orient="horizontal",
            mode="determinate",
            maximum=100,
            length=1000
        )

        self.progress.place(
            relx=0.5,
            rely=0.92,
            anchor="center"
        )

        # --------------------------------------------------
        # VERSÃO
        # --------------------------------------------------

        tk.Label(
            self.overlay,
            text="Version 1.0",
            font=("Arial", 10),
            fg="#BBBBBB",
            bg="#000000"
        ).place(
            relx=0.98,
            rely=0.97,
            anchor="e"
        )

    # ======================================================
    # CARREGAMENTO
    # ======================================================

    def load_modules(self):

        modules = [
            "Certificate Manager",
            "RSA Engine",
            "Prime Generator",
            "Key Manager",
            "Digital Signature Module",
            "Encryption Engine",
            "Integrity Validator",
            "PKI Framework",
            "Security Policies",
            "User Interface",
            "System Ready"
        ]

        if self.progress_value < 100:

            self.progress_value += 1

            self.progress["value"] = self.progress_value

            index = min(
                self.progress_value // 10,
                len(modules) - 1
            )

            self.lbl_status.config(
                text=f"Loading: {modules[index]}"
            )

            self.after(
                40,
                self.load_modules
            )

        else:

            self.lbl_status.config(
                text="Validating Digital Certificate..."
            )

            self.after(
                1500,
                self.finish
            )

    # ======================================================
    # FINALIZAÇÃO
    # ======================================================

    def finish(self):

        certificado_valido = validar_certificado()

        if not certificado_valido:

            messagebox.showerror(
                "Authentication Failure",
                (
                    "Required digital certificate not found.\n\n"
                    "Security validation failed.\n\n"
                    "The application will be terminated."
                )
            )

            try:
                self.parent.destroy()
            except:
                pass

            self.destroy()

            sys.exit()

        self.lbl_status.config(
            text="Certificate Validated"
        )

        self.after(
            500,
            self.open_main_application
        )

    # ======================================================
    # ABRIR APLICAÇÃO PRINCIPAL
    # ======================================================

    def open_main_application(self):

        self.destroy()

        self.parent.deiconify()