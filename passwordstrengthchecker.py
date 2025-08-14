# -*- coding: utf-8 -*-
# 🚀 Cybersecurity Project: Password Strength & Breach Analyzer
# 🔍 Checks strength using entropy, patterns, and best practices
# 🛡️ Verifies password safety with HaveIBeenPwned API (k-anonymity)
# 💻 Built with Python + Tkinter | Made for ethical hacking & security awareness

# -*- coding: utf-8 -*-
# PASSWORD INTEL ANALYZER - FINAL ANIMATED VERSION
import tkinter as tk
from tkinter import ttk
import threading, queue, re, math, hashlib, requests, time

# --------- Colors ----------
BG           = "#0D0D0D"
CARD         = "#141414"
NEON_GREEN   = "#00FF41"
NEON_YELLOW  = "#FFD60A"
NEON_RED     = "#FF3357"
NEON_CYAN    = "#00E5FF"
MUTED        = "#9CA3AF"
TEXT         = "#E5E7EB"

# --------- Password analytics ----------
def calculate_entropy(pw: str) -> float:
    charset = 0
    if re.search(r'[a-z]', pw): charset += 26
    if re.search(r'[A-Z]', pw): charset += 26
    if re.search(r'[0-9]', pw): charset += 10
    if re.search(r'[^a-zA-Z0-9]', pw): charset += 32
    return (len(pw) * math.log2(charset)) if charset else 0.0

def strength_bucket(pw: str):
    length_ok = len(pw) >= 12
    lower     = bool(re.search(r'[a-z]', pw))
    upper     = bool(re.search(r'[A-Z]', pw))
    digit     = bool(re.search(r'\d', pw))
    special   = bool(re.search(r'[^a-zA-Z0-9]', pw))
    entropy   = calculate_entropy(pw)
    score     = sum([length_ok, lower, upper, digit, special])
    rules_norm   = score / 5
    entropy_norm = min(entropy, 80) / 80
    progress     = 0.6 * rules_norm + 0.4 * entropy_norm
    if progress >= 0.8 and entropy >= 60:
        label, color = "STRONG ✅", NEON_GREEN
    elif progress >= 0.55 and entropy >= 40:
        label, color = "MEDIUM ⚠️", NEON_YELLOW
    else:
        label, color = "WEAK ❌", NEON_RED
    suggestions = []
    if len(pw) < 12: suggestions.append("Use ≥ 12 characters (prefer 16+).")
    if not lower:    suggestions.append("Add lowercase letters.")
    if not upper:    suggestions.append("Add uppercase letters.")
    if not digit:    suggestions.append("Include some digits.")
    if not special:  suggestions.append("Mix special symbols (!@#...).")
    if pw and re.fullmatch(r'(.)\1+', pw): suggestions.append("Avoid repeated characters.")
    if pw and re.search(r'(password|qwerty|admin|1234|iloveyou)', pw, re.I):
        suggestions.append("Avoid common words/sequences.")
    return {"progress": float(progress), "label": label, "color": color,
            "entropy": entropy, "suggestions": suggestions}

def pretty_bruteforce_time(entropy_bits: float, guesses_per_sec=1e9):
    seconds = 0.5 * (2 ** entropy_bits) / guesses_per_sec if entropy_bits > 0 else 0
    units = [("y", 365*24*3600), ("d", 24*3600), ("h", 3600), ("min", 60), ("s", 1)]
    out = []
    for name, secs in units:
        if seconds >= secs:
            val = int(seconds // secs); seconds -= val * secs
            out.append(f"{val}{name}")
        if len(out) >= 2: break
    return " ~" + (" ".join(out) if out else "0s")

# --------- HIBP breach ----------
def hibp_breach_count(pw: str) -> int:
    if len(pw) < 4: return 0
    sha1 = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        r = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=6)
        if r.status_code != 200: return -1
        for line in r.text.splitlines():
            if ':' not in line: continue
            sfx, count = line.split(':')
            if sfx.upper() == suffix.upper():
                return int(count)
        return 0
    except Exception:
        return -1

# --------- App ----------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PASSWORD INTEL ANALYZER")
        self.geometry("860x540")
        self.configure(bg=BG)
        self._blink = False
        self._q = queue.Queue()
        self._last_pw = None

        self.wm_attributes('-alpha', 0)  # start transparent
        self.protocol("WM_DELETE_WINDOW", self.fade_out)

        self._make_style()
        self.intro_frame = tk.Frame(self, bg=BG)
        self.intro_frame.pack(expand=True, fill="both")
        self.intro_label = tk.Label(self.intro_frame, text="", font=("Consolas", 16), fg=NEON_GREEN, bg=BG)
        self.intro_label.pack(pady=50)
        self.intro_text = [
            ">>> Initializing CyberShield...",
            ">>> Loading breach detection modules...",
            ">>> Ready to analyze!"
        ]
        self.after(100, self.fade_in)
        self.after(500, self.type_intro, 0, 0)

    # Fade-in/out
    def fade_in(self):
        for i in range(0, 11):
            self.wm_attributes('-alpha', i/10)
            self.update()
            time.sleep(0.03)
    def fade_out(self):
        for i in range(10, -1, -1):
            self.wm_attributes('-alpha', i/10)
            self.update()
            time.sleep(0.03)
        self.destroy()

    # Terminal typing intro
    def type_intro(self, line_index, char_index):
        if line_index < len(self.intro_text):
            line = self.intro_text[line_index]
            current = self.intro_label.cget("text")
            if char_index < len(line):
                self.intro_label.config(text=current + line[char_index])
                self.after(30, self.type_intro, line_index, char_index+1)
            else:
                self.intro_label.config(text=current + "\n")
                self.after(500, self.type_intro, line_index+1, 0)
        else:
            self.intro_frame.destroy()
            self._build_ui()
            self.after(500, self._cursor_blink)
            self.after(120, self._pump_breach)

    def _make_style(self):
        self.style = ttk.Style(self)
        self.style.theme_use("clam")
        self.style.configure("Card.TFrame", background=CARD)
        self.style.configure("Title.TLabel", background=BG, foreground=NEON_GREEN, font=("Consolas", 22, "bold"))
        self.style.configure("Sub.TLabel", background=CARD, foreground=MUTED, font=("Consolas", 12))
        self.style.configure("Text.TLabel", background=CARD, foreground=TEXT, font=("Consolas", 12, "bold"))
        self.style.configure("Entry.TEntry", fieldbackground="#0F1316", background="#0F1316", foreground=TEXT,
                             bordercolor=NEON_CYAN, lightcolor=NEON_CYAN, darkcolor=NEON_CYAN)
        self.style.configure("Meter.Horizontal.TProgressbar", troughcolor="#0F1316", background=NEON_RED,
                             bordercolor="#1f2937", lightcolor=NEON_RED, darkcolor=NEON_RED)
        self.style.configure("Primary.TButton", background=NEON_CYAN, foreground="#031013",
                             font=("Consolas", 11, "bold"))

    def _build_ui(self):
        self.title_lbl = ttk.Label(self, text=">>> PASSWORD INTEL ANALYZER _", style="Title.TLabel")
        self.title_lbl.pack(pady=(16,8))

        self.card = ttk.Frame(self, style="Card.TFrame", padding=16)
        self.card.pack(fill="x", padx=16, pady=6)

        ttk.Label(self.card, text="INPUT PASSWORD", style="Sub.TLabel").pack(anchor="w")
        row = ttk.Frame(self.card, style="Card.TFrame")
        row.pack(fill="x", pady=(6, 8))

        self.pw_var = tk.StringVar()
        self.entry = ttk.Entry(row, textvariable=self.pw_var, style="Entry.TEntry", show="•", font=("Consolas", 13))
        self.entry.pack(side="left", fill="x", expand=True)
        self.entry.bind("<KeyRelease>", self.on_pw_change)

        self.toggle = ttk.Button(row, text="SHOW", style="Primary.TButton", command=self.toggle_show)
        self.toggle.pack(side="left", padx=(10,0))

        self.str_lbl = ttk.Label(self.card, text="STRENGTH: —", style="Text.TLabel")
        self.str_lbl.pack(anchor="w", pady=(6, 4))

        self.meter = ttk.Progressbar(self.card, style="Meter.Horizontal.TProgressbar",
                                     orient="horizontal", length=100, mode="determinate", maximum=100)
        self.meter.pack(fill="x")

        stats = ttk.Frame(self.card, style="Card.TFrame")
        stats.pack(fill="x", pady=(8, 4))
        self.ent_lbl = ttk.Label(stats, text="Entropy: 0.0 bits", style="Sub.TLabel")
        self.ent_lbl.pack(side="left")
        self.time_lbl = ttk.Label(stats, text="Bruteforce (1e9/s): ~0s", style="Sub.TLabel")
        self.time_lbl.pack(side="right")

        self.breach = ttk.Label(self.card, text="Breach status: —", style="Text.TLabel")
        self.breach.pack(anchor="w", pady=(8, 8))

        ttk.Label(self.card, text="SUGGESTIONS", style="Sub.TLabel").pack(anchor="w")
        self.sug = tk.Text(self.card, height=7, relief="flat", bg="#0F1316", fg=TEXT,
                           insertbackground=NEON_CYAN, font=("Consolas", 11))
        self.sug.pack(fill="x", pady=(6, 2))
        self.sug.configure(state="normal"); self.sug.insert("1.0", "• Start typing to analyze…"); self.sug.configure(state="disabled")
        ttk.Label(self, text="Note: HIBP uses k-anonymity (only first 5 hex chars of SHA-1 hash sent).",
                  style="Sub.TLabel").pack(pady=(6, 10))
        self.entry.focus_set()

    def _set_meter_color(self, color_hex):
        self.style.configure("Meter.Horizontal.TProgressbar",
                             troughcolor="#0F1316", background=color_hex,
                             lightcolor=color_hex, darkcolor=color_hex)

    def _write_suggestions(self, lines):
        self.sug.configure(state="normal"); self.sug.delete("1.0", "end")
        if not lines:
            self.sug.insert("1.0", "• Looks solid. Consider a pass-phrase (4+ random words).")
        else:
            for s in lines:
                self.sug.insert("end", f"• {s}\n")
        self.sug.configure(state="disabled")

    def toggle_show(self):
        if self.entry.cget("show") == "•":
            self.entry.config(show=""); self.toggle.config(text="HIDE")
        else:
            self.entry.config(show="•"); self.toggle.config(text="SHOW")

    # Password update
    def on_pw_change(self, _=None):
        pw = self.pw_var.get()
        info = strength_bucket(pw)
        self.str_lbl.config(text=f"STRENGTH: {info['label']}", foreground=info["color"])
        self._animate_meter(int(info["progress"] * 100))
        ent = info["entropy"]
        self.ent_lbl.config(text=f"Entropy: {ent:.1f} bits")
        self.time_lbl.config(text=f"Bruteforce (1e9/s):{pretty_bruteforce_time(ent)}")
        self._write_suggestions(info["suggestions"])
        self.breach.config(text="Breach status: checking…", foreground=MUTED)
        self._queue_breach(pw)

    def _animate_meter(self, target, steps=8):
        current = self.meter["value"]
        delta = (target - current) / max(1, steps)
        def tick(i=0):
            self.meter["value"] = max(0, min(100, self.meter["value"] + delta))
            pulse_intensity = abs((i % 4) - 2) * 40
            if self.meter["value"] > 70: glow_color = NEON_GREEN
            elif self.meter["value"] > 40: glow_color = NEON_YELLOW
            else: glow_color = NEON_RED
            self._set_meter_color(glow_color)
            if i < steps-1:
                self.after(18, lambda: tick(i+1))
        tick()

    # Breach async
    def _queue_breach(self, pw):
        self._last_pw = pw
        def worker(pw_val, out_q):
            count = hibp_breach_count(pw_val) if len(pw_val) >= 4 else 0
            out_q.put((pw_val, count))
        threading.Thread(target=worker, args=(pw, self._q), daemon=True).start()

    def _pump_breach(self):
        try:
            while True:
                pw_val, count = self._q.get_nowait()
                if pw_val != self._last_pw:
                    continue
                if count > 0:
                    self.breach.config(text=f"Breach status: ⚠️ FOUND in {count:,} breaches", foreground=NEON_RED)
                elif count == 0:
                    self.breach.config(text="Breach status: ✅ Not found in known breaches", foreground=NEON_GREEN)
                else:
                    self.breach.config(text="Breach status: API unreachable (offline)", foreground=NEON_YELLOW)
        except queue.Empty:
            pass
        self._blink_breach_if_needed()
        self.after(120, self._pump_breach)

    def _blink_breach_if_needed(self):
        text = self.breach.cget("text")
        if "FOUND" in text:
            self._blink = not self._blink
            self.breach.config(foreground=NEON_RED if self._blink else "#8b0015")
        else:
            self._blink = False

    def _cursor_blink(self):
        t = self.title_lbl.cget("text")
        self.title_lbl.config(text=(t[:-1] + " " if t.endswith("_") else t[:-1] + "_"))
        self.after(520, self._cursor_blink)

if __name__ == "__main__":
    App().mainloop()



