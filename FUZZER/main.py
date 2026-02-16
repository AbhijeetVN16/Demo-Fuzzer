import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import time
from vulnerability_tests import VulnerabilityScanner

class CleanFuzzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("UDS Vulnerability Exploit Lab")
        self.root.geometry("900x700")
        self.root.configure(bg="#1e1e1e")
        
        try:
            self.scanner = VulnerabilityScanner()
            self.status_msg = "ECU STATE: CONNECTED"
            self.status_color = "#00ff41"
        except Exception as e:
            self.status_msg = f"CAN ERROR: {e}"
            self.status_color = "#ff4444"

        self._setup_ui()

    def _setup_ui(self):
        # Title
        tk.Label(self.root, text="UDS EXPLOIT CONTROL PANEL", font=("Segoe UI", 18, "bold"), bg="#1e1e1e", fg="#00d4ff").pack(pady=20)

        # Status
        self.ecu_status = tk.Label(self.root, text=self.status_msg, font=("Consolas", 12), bg="#1e1e1e", fg=self.status_color)
        self.ecu_status.pack(padx=30, anchor="w")

        # Attack Grid
        grid_frame = tk.LabelFrame(self.root, text=" Targeted Vulnerabilities ", font=("Segoe UI", 10, "bold"), bg="#1e1e1e", fg="white", bd=2)
        grid_frame.pack(fill="x", padx=30, pady=10)

        attacks = [
            ("Fuzz Static Seed (V6)", self.run_v6, 0, 0),
            ("Magic Byte Bypass (V2)", self.run_v2, 0, 1),
            ("Session Leak (V5)", self.run_v5, 1, 0),
            ("VIN Buffer Overflow (V1)", self.run_v1, 1, 1),
            ("ISO-TP Seq Attack (V4)", self.run_v4, 2, 0),
            ("Resource DoS (V3)", self.run_v3, 2, 1),
        ]

        for text, cmd, r, c in attacks:
            btn = tk.Button(grid_frame, text=text, command=lambda m=cmd: self._thread_run(m),
                          font=("Segoe UI", 10), bg="#333333", fg="white", width=30, pady=8, bd=0)
            btn.grid(row=r, column=c, padx=15, pady=10)

        # Log
        self.log_widget = scrolledtext.ScrolledText(self.root, bg="#000000", fg="#00ff41", font=("Consolas", 10))
        self.log_widget.pack(fill="both", expand=True, padx=30, pady=20)

    def log(self, msg, type="INFO"):
        ts = time.strftime("%H:%M:%S")
        self.log_widget.insert(tk.END, f"[{ts}] [{type}] {msg}\n")
        self.log_widget.see(tk.END)

    def _thread_run(self, target):
        threading.Thread(target=target, daemon=True).start()

    # Wrapper methods to update UI based on scanner results
    def run_v1(self):
        self.log("Testing VIN Overflow...", "ATTACK")
        if self.scanner.test_v1_vin_overflow():
            self.log("VULN FOUND: ECU CRASHED!", "CRITICAL")
            self.ecu_status.config(text="ECU STATE: OFFLINE", fg="#ff4444")
        else: self.log("VULN-001: Passed.")

    def run_v2(self):
        self.log("Testing Magic Byte...", "ATTACK")
        res = self.scanner.test_v2_magic_byte()
        self.log(f"Result: {'VULN FOUND' if res else 'Passed'}", "CRITICAL" if res else "INFO")

    def run_v3(self):
        self.log("Starting DoS Flood...", "ATTACK")
        if self.scanner.test_v3_resource_exhaustion():
            self.log("VULN FOUND: ECU HANGING!", "CRITICAL")
        else: self.log("VULN-003: Passed.")

    def run_v4(self):
        self.log("Testing ISO-TP Overlap...", "ATTACK")
        if self.scanner.test_v4_isotp_overlap():
            self.log("VULN FOUND: Engine Crashed!", "CRITICAL")
        else: self.log("VULN-004: Passed.")

    def run_v5(self):
        self.log("Testing Session Leak...", "LOGIC")
        res = self.scanner.test_v5_session_leak()
        self.log(f"Result: {'VULN FOUND' if res else 'Passed'}", "CRITICAL" if res else "INFO")

    def run_v6(self):
        self.log("Checking Seed...", "SCAN")
        res = self.scanner.test_v6_weak_seed()
        self.log(f"Result: {'STATIC SEED FOUND' if res else 'Normal'}", "CRITICAL" if res else "INFO")

if __name__ == "__main__":
    root = tk.Tk()
    app = CleanFuzzerGUI(root)
    root.mainloop()
