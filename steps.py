import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import pandas as pd
import os
from pii_detector import detect_pii, get_pii_type_names
from anonymizer import TECHNIQUE_NAMES, apply_technique, export_pseudo_key, clear_pseudo_mapping
from profiles import get_profile_names, get_profile, get_technique_for_pii
from audit import generate_audit_report

BG="#1a1a2e"; PANEL="#16213e"; ACCENT="#0f3460"; HIGHLIGHT="#e94560"
TEXT="#e0e0e0"; SUBTEXT="#a0a0c0"; SUCCESS="#4ecca3"
BTN_BG="#0f3460"; BTN_FG="#ffffff"
FH=("Segoe UI",14,"bold"); FB=("Segoe UI",10,"bold"); FN=("Segoe UI",10); FS=("Segoe UI",9)

def mk_title(parent, text):
    tk.Label(parent, text=text, bg=BG, fg=HIGHLIGHT, font=FH, anchor="w").pack(fill=tk.X, padx=20, pady=(18,4))

def mk_sep(parent):
    ttk.Separator(parent, orient="horizontal").pack(fill=tk.X, padx=20, pady=6)

def mk_btn(parent, text, cmd, color=ACCENT):
    return tk.Button(parent, text=text, command=cmd, bg=color, fg=BTN_FG,
                     font=FB, relief="flat", padx=14, pady=6, cursor="hand2")

class BaseStep(tk.Frame):
    def __init__(self, parent, state, app):
        super().__init__(parent, bg=BG)
        self.state = state
        self.app = app
    def on_enter(self): pass
    def validate(self): return True
    def reset(self): pass   # subclasses override to clear their widgets


# ── STEP 1: LOAD CSV ──────────────────────────────────────────────────────────
class Step1Load(BaseStep):
    def __init__(self, parent, state, app):
        super().__init__(parent, state, app)
        mk_title(self, "Step 1 - Load CSV File")
        mk_sep(self)
        tk.Label(self, text=(
            "Select a CSV file containing personal data to anonymize.\n"
            "The tool will preview the first 5 rows before any processing."
        ), bg=BG, fg=SUBTEXT, font=FN, justify="left").pack(padx=20, anchor="w")

        row = tk.Frame(self, bg=BG)
        row.pack(fill=tk.X, padx=20, pady=12)
        row.columnconfigure(0, weight=1)  # path label expands
        row.columnconfigure(1, weight=0)  # button stays fixed
        self.path_var = tk.StringVar(value="No file selected")
        tk.Label(row, textvariable=self.path_var, bg=PANEL, fg=TEXT,
                 font=FN, anchor="w", padx=10, pady=6).grid(row=0, column=0, sticky="ew")
        mk_btn(row, "📂 Browse", self._browse, ACCENT).grid(row=0, column=1, padx=(8,0), sticky="e")

        # Preview table
        tf = tk.Frame(self, bg=PANEL, padx=10, pady=10)
        tf.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        tk.Label(tf, text="Data Preview (first 5 rows)", bg=PANEL, fg=SUCCESS, font=FB).pack(anchor="w")
        cols_frame = tk.Frame(tf, bg=PANEL)
        cols_frame.pack(fill=tk.BOTH, expand=True, pady=6)
        self.tree = ttk.Treeview(cols_frame, show="headings", height=7)
        sb_x = ttk.Scrollbar(cols_frame, orient="horizontal", command=self.tree.xview)
        sb_y = ttk.Scrollbar(cols_frame, orient="vertical",   command=self.tree.yview)
        self.tree.configure(xscrollcommand=sb_x.set, yscrollcommand=sb_y.set)
        sb_y.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb_x.pack(fill=tk.X)

        self.info_var = tk.StringVar(value="")
        tk.Label(self, textvariable=self.info_var, bg=BG, fg=SUCCESS, font=FN).pack(padx=20, anchor="w")

    def _browse(self):
        path = filedialog.askopenfilename(filetypes=[("CSV Files","*.csv"),("All","*.*")])
        if not path: return
        try:
            df = pd.read_csv(path)
            self.state.csv_path = path
            self.state.dataframe = df
            self.path_var.set(path)
            self._load_preview(df)
            self.info_var.set(f"✔ Loaded: {len(df):,} rows × {len(df.columns)} columns")
            self.app.set_status(f"Loaded: {os.path.basename(path)}")
        except Exception as e:
            messagebox.showerror("Load Error", f"Could not read CSV:\n{e}")

    def _load_preview(self, df):
        self.tree.delete(*self.tree.get_children())
        self.tree["columns"] = list(df.columns)
        # Set column width proportional to number of columns, min 90
        col_w = max(90, min(160, 900 // max(len(df.columns), 1)))
        for c in df.columns:
            self.tree.heading(c, text=c, anchor="w")
            self.tree.column(c, width=col_w, minwidth=70, stretch=True)
        for _, row in df.head(5).iterrows():
            self.tree.insert("", tk.END, values=list(row.astype(str)))

    def validate(self):
        if self.state.dataframe is None:
            messagebox.showwarning("No File", "Please load a CSV file first.")
            return False
        return True

    def reset(self):
        self.path_var.set("No file selected")
        self.info_var.set("")
        self.tree.delete(*self.tree.get_children())
        self.tree["columns"] = []


# ── STEP 2: DETECT PII ────────────────────────────────────────────────────────
class Step2Detect(BaseStep):
    def __init__(self, parent, state, app):
        super().__init__(parent, state, app)
        mk_title(self, "Step 2 - PII Detection & Manual Override")
        mk_sep(self)
        tk.Label(self, text=(
            "Auto-detected PII columns are shown below.\n"
            "Use dropdowns to change the PII type or uncheck Include to skip a column."
        ), bg=BG, fg=SUBTEXT, font=FN).pack(padx=20, anchor="w")

        btn_row = tk.Frame(self, bg=BG)
        btn_row.pack(fill=tk.X, padx=20, pady=8)
        mk_btn(btn_row, "🔍 Run Auto-Detect", self._run_detect, HIGHLIGHT).pack(side=tk.LEFT)
        mk_btn(btn_row, "➕ Add Column Manually", self._add_manual, ACCENT).pack(side=tk.LEFT, padx=8)

        # Scrollable table area
        container = tk.Frame(self, bg=BG)
        container.pack(fill=tk.BOTH, expand=True, padx=20, pady=6)
        canvas = tk.Canvas(container, bg=PANEL, highlightthickness=0)
        sb = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.table_frame = tk.Frame(canvas, bg=PANEL)
        self.canvas_window = canvas.create_window((0,0), window=self.table_frame, anchor="nw")
        self.table_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(self.canvas_window, width=e.width))
        self.canvas = canvas
        self._row_widgets = []   # list of dicts per detected column

    def on_enter(self):
        if self.state.dataframe is not None and not self.state.detected_pii:
            self._run_detect()

    def _run_detect(self):
        if self.state.dataframe is None: return
        self.state.detected_pii = detect_pii(self.state.dataframe)
        self._render_table()
        self.app.set_status(f"Detected {len(self.state.detected_pii)} PII column(s).")

    def _render_table(self):
        for w in self.table_frame.winfo_children():
            w.destroy()
        self._row_widgets = []
        headers = ["Include", "Column", "Detected As", "Method", "Override PII Type"]
        for c, h in enumerate(headers):
            tk.Label(self.table_frame, text=h, bg=ACCENT, fg=BTN_FG,
                     font=FB, padx=8, pady=6).grid(row=0, column=c, sticky="ew", padx=2, pady=2)
        pii_names = ["(none)"] + get_pii_type_names()
        for r, (col, info) in enumerate(self.state.detected_pii.items(), start=1):
            inc_var = tk.BooleanVar(value=info.get("include", True))
            tk.Checkbutton(self.table_frame, variable=inc_var, bg=PANEL,
                           activebackground=PANEL).grid(row=r, column=0, padx=6)
            tk.Label(self.table_frame, text=col, bg=PANEL, fg=TEXT,
                     font=FN, padx=8).grid(row=r, column=1, sticky="w")
            tk.Label(self.table_frame, text=info["pii_type"], bg=PANEL,
                     fg=SUCCESS, font=FN).grid(row=r, column=2)
            tk.Label(self.table_frame, text=info["method"], bg=PANEL,
                     fg=SUBTEXT, font=FS).grid(row=r, column=3)
            override_var = tk.StringVar(value=info["pii_type"])
            ttk.Combobox(self.table_frame, textvariable=override_var,
                         values=pii_names, width=20, state="readonly").grid(row=r, column=4, padx=6)
            self._row_widgets.append({
                "col": col, "inc_var": inc_var, "override_var": override_var
            })

    def _add_manual(self):
        if self.state.dataframe is None: return
        all_cols = list(self.state.dataframe.columns)
        win = tk.Toplevel(self.app.root); win.title("Add Column Manually")
        win.configure(bg=BG); win.geometry("340x180")
        tk.Label(win, text="Column:", bg=BG, fg=TEXT, font=FN).pack(pady=(12,2))
        col_var = tk.StringVar()
        ttk.Combobox(win, textvariable=col_var, values=all_cols, width=30).pack()
        tk.Label(win, text="PII Type:", bg=BG, fg=TEXT, font=FN).pack(pady=(8,2))
        pii_var = tk.StringVar()
        ttk.Combobox(win, textvariable=pii_var, values=get_pii_type_names(), width=30).pack()
        def confirm():
            c = col_var.get(); p = pii_var.get()
            if c and p:
                self.state.detected_pii[c] = {"pii_type":p,"method":"manual","default_tech":"Masking","include":True}
                self._render_table(); win.destroy()
        mk_btn(win, "Add", confirm, HIGHLIGHT).pack(pady=10)

    def validate(self):
        for rw in self._row_widgets:
            col = rw["col"]
            if col in self.state.detected_pii:
                self.state.detected_pii[col]["include"] = rw["inc_var"].get()
                ov = rw["override_var"].get()
                if ov and ov != "(none)":
                    self.state.detected_pii[col]["pii_type"] = ov
        return True

    def reset(self):
        self._row_widgets = []
        for w in self.table_frame.winfo_children():
            w.destroy()


# ── STEP 3: CONFIGURE ─────────────────────────────────────────────────────────
class Step3Configure(BaseStep):
    def __init__(self, parent, state, app):
        super().__init__(parent, state, app)
        mk_title(self, "Step 3 - Configure Processing")
        mk_sep(self)

        top = tk.Frame(self, bg=BG)
        top.pack(fill=tk.X, padx=20, pady=6)

        # Mode selection
        mode_f = tk.LabelFrame(top, text=" Processing Mode ", bg=BG, fg=SUCCESS,
                               font=FB, padx=10, pady=8)
        mode_f.pack(side=tk.LEFT, padx=(0,20))
        self.state.mode.set("Anonymization")
        for m in ("Anonymization", "Pseudonymization"):
            tk.Radiobutton(mode_f, text=m, variable=self.state.mode, value=m,
                           bg=BG, fg=TEXT, font=FN, selectcolor=ACCENT,
                           activebackground=BG).pack(anchor="w")
        tk.Label(mode_f,
                 text="Anonymization = irreversible\nPseudonymization = reversible (key saved)",
                 bg=BG, fg=SUBTEXT, font=FS).pack(anchor="w", pady=(4,0))

        # Profile selection
        prof_f = tk.LabelFrame(top, text=" Use-Case Profile ", bg=BG, fg=SUCCESS,
                               font=FB, padx=10, pady=8)
        prof_f.pack(side=tk.LEFT)
        self.state.profile.set("Academic/Research")
        ttk.Combobox(prof_f, textvariable=self.state.profile,
                     values=get_profile_names(), state="readonly", width=22).pack()
        mk_btn(prof_f, "Apply Profile Defaults", self._apply_profile, ACCENT).pack(pady=(8,0))

        mk_sep(self)
        tk.Label(self, text="Per-Column Technique Selection", bg=BG, fg=TEXT, font=FB).pack(padx=20, anchor="w")

        # Scrollable technique table
        cont = tk.Frame(self, bg=BG)
        cont.pack(fill=tk.BOTH, expand=True, padx=20, pady=6)
        canvas = tk.Canvas(cont, bg=PANEL, highlightthickness=0)
        sb = ttk.Scrollbar(cont, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y); canvas.pack(fill=tk.BOTH, expand=True)
        self.cfg_frame = tk.Frame(canvas, bg=PANEL)
        win_id = canvas.create_window((0,0), window=self.cfg_frame, anchor="nw")
        self.cfg_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(win_id, width=e.width))
        self._tech_vars = {}   # { col_name: StringVar for technique }

    def on_enter(self):
        self._build_tech_table()

    def _build_tech_table(self):
        for w in self.cfg_frame.winfo_children(): w.destroy()
        self._tech_vars = {}
        headers = ["Column", "PII Type", "Technique"]
        for c, h in enumerate(headers):
            tk.Label(self.cfg_frame, text=h, bg=ACCENT, fg=BTN_FG,
                     font=FB, padx=10, pady=6).grid(row=0, column=c, sticky="ew", padx=2, pady=2)
        for r, (col, info) in enumerate(self.state.detected_pii.items(), start=1):
            if not info.get("include", True): continue
            tk.Label(self.cfg_frame, text=col, bg=PANEL, fg=TEXT,
                     font=FN, padx=8, anchor="w").grid(row=r, column=0, sticky="w")
            tk.Label(self.cfg_frame, text=info["pii_type"], bg=PANEL,
                     fg=SUCCESS, font=FN).grid(row=r, column=1)
            prev = self.state.column_config.get(col, {}).get("technique", info["default_tech"])
            var = tk.StringVar(value=prev)
            ttk.Combobox(self.cfg_frame, textvariable=var,
                         values=TECHNIQUE_NAMES, state="readonly", width=20).grid(row=r, column=2, padx=8)
            self._tech_vars[col] = var

    def _apply_profile(self):
        prof_name = self.state.profile.get()
        for col, info in self.state.detected_pii.items():
            tech = get_technique_for_pii(prof_name, info["pii_type"])
            if col in self._tech_vars:
                self._tech_vars[col].set(tech)
        self.app.set_status(f"Profile '{prof_name}' applied.")

    def validate(self):
        self.state.column_config = {}
        for col, info in self.state.detected_pii.items():
            if not info.get("include", True): continue
            tech = self._tech_vars.get(col, tk.StringVar(value="Masking")).get()
            self.state.column_config[col] = {
                "pii_type" : info["pii_type"],
                "technique": tech,
                "include"  : True
            }
        if not self.state.column_config:
            messagebox.showwarning("Nothing Selected", "No columns are configured for processing.")
            return False
        return True

    def reset(self):
        self._tech_vars = {}
        for w in self.cfg_frame.winfo_children():
            w.destroy()


# ── STEP 4: PREVIEW ───────────────────────────────────────────────────────────
class Step4Preview(BaseStep):
    def __init__(self, parent, state, app):
        super().__init__(parent, state, app)
        mk_title(self, "Step 4 - Preview Changes")
        mk_sep(self)

        top = tk.Frame(self, bg=BG)
        top.pack(fill=tk.X, padx=20, pady=(0, 6))
        tk.Label(top, text="Sample of first 3 rows — BEFORE and AFTER transformation.",
                 bg=BG, fg=SUBTEXT, font=FN).pack(side=tk.LEFT, anchor="w")
        mk_btn(top, "🔄 Refresh Preview", self._generate, HIGHLIGHT).pack(side=tk.RIGHT)

        # ── BEFORE panel ─────────────────────────────────────────────────────
        before_outer = tk.Frame(self, bg=PANEL, bd=0)
        before_outer.pack(fill=tk.BOTH, expand=True, padx=20, pady=(4, 2))
        hdr_b = tk.Frame(before_outer, bg="#0d2137", padx=10, pady=6)
        hdr_b.pack(fill=tk.X)
        tk.Label(hdr_b, text="◀  BEFORE  (Original Data)", bg="#0d2137",
                 fg=TEXT, font=FB).pack(side=tk.LEFT)
        self.before_count = tk.Label(hdr_b, text="", bg="#0d2137", fg=SUBTEXT, font=FS)
        self.before_count.pack(side=tk.RIGHT)
        self.before_tree, _ = self._mk_tree(before_outer)

        # ── AFTER panel ──────────────────────────────────────────────────────
        after_outer = tk.Frame(self, bg=PANEL, bd=0)
        after_outer.pack(fill=tk.BOTH, expand=True, padx=20, pady=(2, 8))
        hdr_a = tk.Frame(after_outer, bg="#0d3320", padx=10, pady=6)
        hdr_a.pack(fill=tk.X)
        tk.Label(hdr_a, text="▶  AFTER  (Transformed Data)", bg="#0d3320",
                 fg=SUCCESS, font=FB).pack(side=tk.LEFT)
        self.after_count = tk.Label(hdr_a, text="", bg="#0d3320", fg=SUBTEXT, font=FS)
        self.after_count.pack(side=tk.RIGHT)
        self.after_tree, _ = self._mk_tree(after_outer)

    def _mk_tree(self, parent):
        """Build a Treeview with both scrollbars inside parent."""
        wrapper = tk.Frame(parent, bg=PANEL)
        wrapper.pack(fill=tk.BOTH, expand=True)
        sb_y = ttk.Scrollbar(wrapper, orient="vertical")
        sb_x = ttk.Scrollbar(wrapper, orient="horizontal")
        tree = ttk.Treeview(wrapper, show="headings", height=4,
                             yscrollcommand=sb_y.set, xscrollcommand=sb_x.set)
        sb_y.config(command=tree.yview)
        sb_x.config(command=tree.xview)
        sb_y.pack(side=tk.RIGHT, fill=tk.Y)
        sb_x.pack(side=tk.BOTTOM, fill=tk.X)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        return tree, wrapper

    def on_enter(self):
        self._generate()

    def _generate(self):
        df = self.state.dataframe
        cfg = self.state.column_config
        if df is None or not cfg:
            return
        sample = df.head(5).copy()
        transformed = sample.copy()
        errors = []
        for col, info in cfg.items():
            if col in transformed.columns:
                try:
                    transformed[col] = apply_technique(
                        transformed[col], info["technique"], info["pii_type"])
                except Exception as e:
                    transformed[col] = f"[ERROR: {e}]"
                    errors.append(col)
        self._fill_tree(self.before_tree, sample)
        self._fill_tree(self.after_tree, transformed)
        n = len(sample)
        self.before_count.config(text=f"{n} row(s) shown")
        self.after_count.config(text=f"{len(cfg)} column(s) transformed" +
                                 (f" | ⚠ {len(errors)} error(s)" if errors else " ✔"))

    def _fill_tree(self, tree, df):
        tree.delete(*tree.get_children())
        cols = list(df.columns)
        tree["columns"] = cols
        col_w = max(80, min(150, 800 // max(len(cols), 1)))
        for c in cols:
            tree.heading(c, text=c, anchor="w")
            tree.column(c, width=col_w, minwidth=60, stretch=True)
        for _, row in df.iterrows():
            tree.insert("", tk.END, values=list(row.astype(str)))

    def reset(self):
        for tree in (self.before_tree, self.after_tree):
            tree.delete(*tree.get_children())
            tree["columns"] = []
        self.before_count.config(text="")
        self.after_count.config(text="")


# ── STEP 5: PROCESS & EXPORT (merged with Results) ───────────────────────────
class Step5Finish(BaseStep):
    """
    Combined processing + results step.
    Left panel: live processing log.
    Right panel: result cards that populate after processing.
    Action buttons (Open Folder, View Report, New Session) sit below.
    """
    def __init__(self, parent, state, app):
        super().__init__(parent, state, app)
        mk_title(self, "Step 5 - Process & Export")
        mk_sep(self)

        # ── Output directory row ──────────────────────────────────────────────
        dir_row = tk.Frame(self, bg=BG)
        dir_row.pack(fill=tk.X, padx=20, pady=(0, 4))
        dir_row.columnconfigure(0, weight=1)
        self.dir_var = tk.StringVar(value="No output directory selected")
        tk.Label(dir_row, textvariable=self.dir_var, bg=PANEL, fg=TEXT,
                 font=FN, anchor="w", padx=10, pady=7).grid(row=0, column=0, sticky="ew")
        mk_btn(dir_row, "📁  Choose Folder", self._pick_dir, ACCENT).grid(
            row=0, column=1, padx=(8, 0), sticky="e")

        # ── Process button ────────────────────────────────────────────────────
        proc_btn = mk_btn(self, "  ⚙  PROCESS & EXPORT  ", self._run_process, HIGHLIGHT)
        proc_btn.config(font=("Segoe UI", 11, "bold"), pady=9)
        proc_btn.pack(padx=20, pady=(8, 6), anchor="w")

        # ── Main two-column area ──────────────────────────────────────────────
        main = tk.Frame(self, bg=BG)
        main.pack(fill=tk.BOTH, expand=True, padx=20, pady=(4, 0))
        main.columnconfigure(0, weight=3)   # log: 60%
        main.columnconfigure(1, weight=2)   # results: 40%
        main.rowconfigure(0, weight=1)

        # Log panel
        log_outer = tk.Frame(main, bg=PANEL)
        log_outer.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        log_hdr = tk.Frame(log_outer, bg="#0d1a30", padx=10, pady=6)
        log_hdr.pack(fill=tk.X)
        tk.Label(log_hdr, text="Processing Log", bg="#0d1a30",
                 fg=SUCCESS, font=FB).pack(side=tk.LEFT)
        self.log_status = tk.Label(log_hdr, text="Idle", bg="#0d1a30",
                                   fg=SUBTEXT, font=FS)
        self.log_status.pack(side=tk.RIGHT)
        log_inner = tk.Frame(log_outer, bg=PANEL)
        log_inner.pack(fill=tk.BOTH, expand=True)
        log_sb = ttk.Scrollbar(log_inner, orient="vertical")
        self.log_text = tk.Text(log_inner, bg="#0d1117", fg="#7ee787",
                                font=("Courier New", 9), state=tk.DISABLED,
                                padx=8, pady=6, wrap=tk.WORD,
                                yscrollcommand=log_sb.set)
        log_sb.config(command=self.log_text.yview)
        log_sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # Results panel
        res_outer = tk.Frame(main, bg=PANEL)
        res_outer.grid(row=0, column=1, sticky="nsew")
        res_hdr = tk.Frame(res_outer, bg="#0d2137", padx=10, pady=6)
        res_hdr.pack(fill=tk.X)
        tk.Label(res_hdr, text="Export Results", bg="#0d2137",
                 fg=SUCCESS, font=FB).pack(side=tk.LEFT)
        res_body = tk.Frame(res_outer, bg=PANEL, padx=8, pady=8)
        res_body.pack(fill=tk.BOTH, expand=True)
        self.csv_lbl = self._mk_result(res_body, "📄 Output CSV",   "–",   TEXT)
        self.rep_lbl = self._mk_result(res_body, "📋 Audit Report", "–",   TEXT)
        self.key_lbl = self._mk_result(res_body, "🔑 Pseudo Key",   "N/A", SUBTEXT,
                                       note="Only generated in Pseudonymization mode")

        # ── Action buttons ────────────────────────────────────────────────────
        btn_row = tk.Frame(self, bg=BG)
        btn_row.pack(fill=tk.X, padx=20, pady=8)
        mk_btn(btn_row, "📂 Open Output Folder", self._open_folder, ACCENT).pack(side=tk.LEFT)
        mk_btn(btn_row, "📋 View Audit Report",  self._view_report, SUCCESS).pack(side=tk.LEFT, padx=8)
        mk_btn(btn_row, "🔄 Start New Session",  self._new_session, HIGHLIGHT).pack(side=tk.LEFT)

        # ── Compact ethical notice ────────────────────────────────────────────
        mk_sep(self)
        note_lbl = tk.Label(self,
            text=("⚠  AUTHORIZED USE ONLY  |  Pseudo key file is SENSITIVE – store it separately from the CSV.  "
                  "Aligned with: GDPR Art.5 · PECA 2016 S.3-4 · HIPAA Security Rule · CIA Triad"),
            bg=PANEL, fg=SUBTEXT, font=FS, justify="left", padx=12, pady=7)
        note_lbl.pack(fill=tk.X, padx=20, pady=(0, 8))
        note_lbl.bind("<Configure>",
                      lambda e: note_lbl.config(wraplength=max(200, e.width - 24)))

    # ── helpers ───────────────────────────────────────────────────────────────

    def _mk_result(self, parent, label, init, color, note=""):
        """Build a labelled result card inside the results panel."""
        card = tk.Frame(parent, bg="#0d2137", padx=10, pady=8)
        card.pack(fill=tk.X, pady=4)
        tk.Label(card, text=label, bg="#0d2137", fg=SUBTEXT, font=FS).pack(anchor="w")
        lbl = tk.Label(card, text=init, bg="#0d2137", fg=color,
                       font=FB, justify="left")
        lbl.pack(anchor="w")
        lbl.bind("<Configure>", lambda e: lbl.config(wraplength=max(100, e.width - 20)))
        if note:
            tk.Label(card, text=note, bg="#0d2137", fg=SUBTEXT,
                     font=("Segoe UI", 8)).pack(anchor="w")
        return lbl

    def _log(self, msg, tag=None):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
        self.app.root.update_idletasks()

    # ── actions ───────────────────────────────────────────────────────────────

    def _pick_dir(self):
        d = filedialog.askdirectory()
        if d:
            self.state.output_dir = d
            self.dir_var.set(d)

    def _run_process(self):
        if not self.state.output_dir:
            messagebox.showwarning("No Output Folder",
                                   "Please choose an output folder first.")
            return
        if self.state.dataframe is None:
            messagebox.showwarning("No Data", "No CSV file loaded. Go to Step 1."); return
        if not self.state.column_config:
            messagebox.showwarning("No Config", "Configure columns in Step 3 first."); return

        # Clear log & result labels
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        self.log_text.config(state=tk.DISABLED)
        self.csv_lbl.config(text="Working…", fg=SUBTEXT)
        self.rep_lbl.config(text="–", fg=TEXT)
        self.key_lbl.config(text="N/A", fg=SUBTEXT)
        self.log_status.config(text="Running…", fg=HIGHLIGHT)

        try:
            from datetime import datetime
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            self._log("=" * 46)
            self._log(f"  Mode    : {self.state.mode.get()}")
            self._log(f"  Profile : {self.state.profile.get()}")
            self._log(f"  Source  : {os.path.basename(self.state.csv_path)}")
            self._log(f"  Columns : {len(self.state.column_config)}")
            self._log("=" * 46)

            df_out = self.state.dataframe.copy()
            clear_pseudo_mapping()

            for col, info in self.state.column_config.items():
                if col not in df_out.columns:
                    continue
                self._log(f"  [{info['technique']:<16}] {col}")
                df_out[col] = apply_technique(
                    df_out[col], info["technique"], info["pii_type"])

            # Save anonymized CSV
            out_name = f"anonymized_{ts}.csv"
            out_csv  = os.path.join(self.state.output_dir, out_name)
            df_out.to_csv(out_csv, index=False)
            self.state.output_csv = out_csv
            self._log(f"\n✔ CSV saved    → {out_name}")
            self.csv_lbl.config(text=out_name, fg=SUCCESS)

            # Pseudo key (only in Pseudonymization mode)
            key_path = None
            if self.state.mode.get() == "Pseudonymization":
                key_name = f"pseudo_key_{ts}.json"
                key_path = os.path.join(self.state.output_dir, key_name)
                export_pseudo_key(key_path, self.state.csv_path,
                                  list(self.state.column_config.keys()))
                self.state.key_path = key_path
                self._log(f"✔ Key saved    → {key_name}")
                self.key_lbl.config(text=f"{key_name}  ⚠ SENSITIVE", fg=HIGHLIGHT)

            # Audit report
            report = generate_audit_report(
                input_file=self.state.csv_path,
                output_file=out_csv,
                mode=self.state.mode.get(),
                profile=self.state.profile.get(),
                column_configs=self.state.column_config,
                row_count=len(df_out),
                output_dir=self.state.output_dir,
                key_file=key_path)
            self.state.report_path = report
            rep_name = os.path.basename(report)
            self._log(f"✔ Report saved → {rep_name}")
            self.rep_lbl.config(text=rep_name, fg=SUCCESS)

            self._log(f"\n✅ Done – {len(df_out):,} rows processed.")
            self.log_status.config(text="Complete ✔", fg=SUCCESS)
            self.app.set_status(
                f"Done – {len(df_out):,} rows · {len(self.state.column_config)} columns processed.")

        except Exception as e:
            messagebox.showerror("Processing Error", str(e))
            self._log(f"\n❌ Error: {e}")
            self.log_status.config(text="Error ✘", fg=HIGHLIGHT)
            self.csv_lbl.config(text="Failed – see log", fg=HIGHLIGHT)

    def _open_folder(self):
        if self.state.output_dir and os.path.isdir(self.state.output_dir):
            os.startfile(self.state.output_dir)
        else:
            messagebox.showinfo("No Folder", "Please process the data first.")

    def _view_report(self):
        if self.state.report_path and os.path.exists(self.state.report_path):
            import subprocess, sys
            if sys.platform == "win32":
                os.startfile(self.state.report_path)
            else:
                subprocess.call(["xdg-open", self.state.report_path])
        else:
            messagebox.showinfo("No Report", "Please process the data first.")

    def _new_session(self):
        if messagebox.askyesno("Start Fresh",
                               "Reset everything and start a new session?\n"
                               "All unsaved progress will be lost."):
            self.app.reset_all_steps()

    # ── reset (called by app.reset_all_steps) ────────────────────────────────

    def reset(self):
        self.dir_var.set("No output directory selected")
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        self.log_text.config(state=tk.DISABLED)
        self.log_status.config(text="Idle", fg=SUBTEXT)
        self.csv_lbl.config(text="–",   fg=TEXT)
        self.rep_lbl.config(text="–",   fg=TEXT)
        self.key_lbl.config(text="N/A", fg=SUBTEXT)

