# =============================================================================
# app.py  –  Main Application Window & Wizard Navigation
# =============================================================================
# Builds the Tkinter root window and hosts the 6-step wizard.
# Each step is a separate Frame managed by the WizardController.
# =============================================================================

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import pandas as pd
import os

# Our own modules
from pii_detector   import detect_pii, get_pii_type_names
from anonymizer     import (apply_technique, export_pseudo_key,
                             clear_pseudo_mapping, TECHNIQUE_NAMES)
from profiles       import get_profile_names, get_profile, get_technique_for_pii
from audit          import generate_audit_report

# ── colour palette ────────────────────────────────────────────────────────────
BG        = "#1a1a2e"   # dark navy background
PANEL     = "#16213e"   # slightly lighter panel
ACCENT    = "#0f3460"   # accent blue
HIGHLIGHT = "#e94560"   # vivid red-pink for highlights
TEXT      = "#e0e0e0"   # light grey text
SUBTEXT   = "#a0a0c0"   # muted text
SUCCESS   = "#4ecca3"   # teal for success states
BTN_BG    = "#0f3460"
BTN_FG    = "#ffffff"
FONT_H    = ("Segoe UI", 14, "bold")
FONT_B    = ("Segoe UI", 10, "bold")
FONT_N    = ("Segoe UI", 10)
FONT_S    = ("Segoe UI",  9)


# =============================================================================
# SHARED APPLICATION STATE
# =============================================================================
# We use a plain Python dict as a simple "state bus" shared across all steps.
# This avoids complex OOP inheritance while keeping data accessible everywhere.
# =============================================================================

class AppState:
    """Holds all shared data for the current session."""
    def __init__(self):
        self.csv_path      = None        # str  – path to loaded CSV
        self.dataframe     = None        # pd.DataFrame – raw loaded data
        self.detected_pii  = {}          # { col: {pii_type, method, default_tech, include} }
        self.column_config = {}          # { col: {pii_type, technique, include} } (user's choices)
        self.mode          = tk.StringVar()   # "Anonymization" or "Pseudonymization"
        self.profile       = tk.StringVar()   # Profile name
        self.output_dir    = None        # str  – directory for output files
        self.output_csv    = None        # str  – path of produced CSV
        self.report_path   = None        # str  – path of audit report
        self.key_path      = None        # str  – path of pseudo key (if applicable)


# =============================================================================
# MAIN APPLICATION CLASS
# =============================================================================

class CSVAnonymizerApp:
    """
    Top-level application class.
    Creates the main window, toolbar, step panels, and navigation buttons.
    """

    STEPS = [
        "1. Load CSV",
        "2. Detect PII",
        "3. Configure",
        "4. Preview",
        "5. Process & Export",
    ]

    def __init__(self, root):
        self.root  = root
        self.state = AppState()
        self._setup_window()
        self._build_sidebar()
        self._build_content_area()
        self._build_nav_buttons()
        self.current_step = 0
        self._show_step(0)

    # ── window setup ──────────────────────────────────────────────────────────

    def _setup_window(self):
        self.root.title("CSV Anonymizer  |  Information Security Academic Tool")
        self.root.geometry("1100x720")
        self.root.minsize(700, 520)   # prevent layout collapse on very small windows
        self.root.configure(bg=BG)
        self.root.resizable(True, True)
        self._apply_ttk_style()

    def _apply_ttk_style(self):
        """Configure ttk widgets to match the dark colour palette."""
        style = ttk.Style(self.root)
        style.theme_use("clam")   # 'clam' allows full colour customisation

        # ── Treeview ────────────────────────────────────────────────────────
        style.configure("Treeview",
            background=PANEL,
            foreground=TEXT,
            fieldbackground=PANEL,
            rowheight=26,
            font=("Segoe UI", 9))
        style.configure("Treeview.Heading",
            background=ACCENT,
            foreground="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief="flat")
        style.map("Treeview.Heading",
            background=[("active", HIGHLIGHT)])
        style.map("Treeview",
            background=[("selected", HIGHLIGHT)],
            foreground=[("selected", "#ffffff")])

        # ── Scrollbar ───────────────────────────────────────────────────────
        style.configure("Vertical.TScrollbar",
            background=ACCENT, troughcolor=PANEL,
            arrowcolor=TEXT, bordercolor=PANEL)
        style.configure("Horizontal.TScrollbar",
            background=ACCENT, troughcolor=PANEL,
            arrowcolor=TEXT, bordercolor=PANEL)

        # ── Combobox ────────────────────────────────────────────────────────
        style.configure("TCombobox",
            fieldbackground=ACCENT,
            background=ACCENT,
            foreground=TEXT,
            selectbackground=HIGHLIGHT,
            selectforeground="#ffffff")
        style.map("TCombobox",
            fieldbackground=[("readonly", ACCENT)],
            foreground=[("readonly", TEXT)])

        # ── Separator ───────────────────────────────────────────────────────
        style.configure("TSeparator", background=ACCENT)

    # ── sidebar: step indicator ───────────────────────────────────────────────

    def _build_sidebar(self):
        sidebar = tk.Frame(self.root, bg=PANEL, width=200)
        sidebar.pack(side=tk.LEFT, fill=tk.Y)
        sidebar.pack_propagate(False)

        # App title
        tk.Label(sidebar, text="🔒 CSV\nAnonymizer",
                 bg=PANEL, fg=HIGHLIGHT,
                 font=("Segoe UI", 16, "bold"),
                 pady=20).pack()

        tk.Label(sidebar, text="Information Security\nAcademic Tool",
                 bg=PANEL, fg=SUBTEXT, font=FONT_S).pack(pady=(0, 20))

        ttk.Separator(sidebar, orient="horizontal").pack(fill=tk.X, padx=10, pady=5)

        # Step labels – stored so we can highlight the active one
        self.step_labels = []
        for i, name in enumerate(self.STEPS):
            lbl = tk.Label(sidebar, text=name, bg=PANEL, fg=SUBTEXT,
                           font=FONT_N, anchor="w", padx=18, pady=8,
                           cursor="arrow")
            lbl.pack(fill=tk.X)
            self.step_labels.append(lbl)

        ttk.Separator(sidebar, orient="horizontal").pack(fill=tk.X, padx=10, pady=10)
        tk.Label(sidebar,
                 text="CIA Triad Focus:\nConfidentiality",
                 bg=PANEL, fg=SUCCESS, font=FONT_S).pack(pady=5)
        tk.Label(sidebar,
                 text="Aligns with:\nGDPR · PECA · HIPAA",
                 bg=PANEL, fg=SUBTEXT, font=FONT_S).pack(pady=5)

    # ── main content area ─────────────────────────────────────────────────────

    def _build_content_area(self):
        """Right-side frame that holds the active step frame."""
        self.content = tk.Frame(self.root, bg=BG)
        self.content.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Import step frames here (avoids circular import at module level)
        from steps import (Step1Load, Step2Detect, Step3Configure,
                           Step4Preview, Step5Finish)

        self.steps = [
            Step1Load     (self.content, self.state, self),
            Step2Detect   (self.content, self.state, self),
            Step3Configure(self.content, self.state, self),
            Step4Preview  (self.content, self.state, self),
            Step5Finish   (self.content, self.state, self),
        ]
        for frame in self.steps:
            frame.place(x=0, y=0, relwidth=1, relheight=1)

    # ── bottom navigation buttons ─────────────────────────────────────────────

    def _build_nav_buttons(self):
        nav = tk.Frame(self.root, bg=PANEL, height=55)
        nav.pack(side=tk.BOTTOM, fill=tk.X)

        self.btn_back = tk.Button(nav, text="◀  Back",
                                  bg=ACCENT, fg=BTN_FG, font=FONT_B,
                                  relief="flat", padx=20, pady=8,
                                  command=self.go_back)
        self.btn_back.pack(side=tk.LEFT, padx=15, pady=8)

        self.btn_next = tk.Button(nav, text="Next  ▶",
                                  bg=HIGHLIGHT, fg=BTN_FG, font=FONT_B,
                                  relief="flat", padx=20, pady=8,
                                  command=self.go_next)
        self.btn_next.pack(side=tk.RIGHT, padx=15, pady=8)

        # Status bar
        self.status_var = tk.StringVar(value="Welcome! Load a CSV file to begin.")
        tk.Label(nav, textvariable=self.status_var,
                 bg=PANEL, fg=SUBTEXT, font=FONT_S).pack(side=tk.LEFT, padx=20)

    # ── navigation logic ──────────────────────────────────────────────────────

    def _show_step(self, index):
        """Activate the frame for step `index` and update sidebar highlight."""
        self.steps[index].tkraise()
        self.steps[index].on_enter()   # Let the step refresh its content
        for i, lbl in enumerate(self.step_labels):
            if i == index:
                lbl.config(fg=HIGHLIGHT, bg=ACCENT, font=FONT_B)
            else:
                lbl.config(fg=SUBTEXT, bg=PANEL, font=FONT_N)
        # Disable Back on first step, hide Next on last step
        self.btn_back.config(state=tk.NORMAL if index > 0 else tk.DISABLED)
        self.btn_next.config(
            text="Next  ▶" if index < len(self.STEPS) - 1 else "Finish",
            state=tk.NORMAL
        )

    def go_next(self):
        """Validate current step then advance."""
        step = self.steps[self.current_step]
        if hasattr(step, "validate") and not step.validate():
            return
        if self.current_step < len(self.steps) - 1:
            self.current_step += 1
            self._show_step(self.current_step)

    def go_back(self):
        if self.current_step > 0:
            self.current_step -= 1
            self._show_step(self.current_step)

    def set_status(self, msg):
        """Update the bottom status bar."""
        self.status_var.set(msg)

    def reset_all_steps(self):
        """
        Full session reset: clears AppState data, calls reset() on every step
        frame to wipe its widgets, then navigates back to Step 1.
        Preserves the Tkinter StringVars inside AppState by re-initialising
        them without recreating the object (avoids breaking widget bindings).
        """
        # Reset data fields while keeping existing StringVar references
        self.state.csv_path     = None
        self.state.dataframe    = None
        self.state.detected_pii = {}
        self.state.column_config = {}
        self.state.mode.set("Anonymization")
        self.state.profile.set("Academic/Research")
        self.state.output_dir   = None
        self.state.output_csv   = None
        self.state.report_path  = None
        self.state.key_path     = None

        # Let each step clear its own visible widgets
        for step in self.steps:
            step.reset()

        # Return to Step 1
        self.current_step = 0
        self._show_step(0)
        self.set_status("Session reset. Load a new CSV file to begin.")
