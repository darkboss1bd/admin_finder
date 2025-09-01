import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import requests
import threading
import time
import random
from concurrent.futures import ThreadPoolExecutor
import os

# --- Configuration ---
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
SUCCESS_CODES = [200, 301, 302, 403]  # Include redirects and forbidden as possible hits

# Hacker-style animation characters
ANIMATION_CHARS = ["█", "▓", "▒", "░", "■", "□", "●", "○", "◆", "◇", "▲", "▼"]

# --- Main App Class ---
class AdminPanelFinder:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 darkboss1bd - Admin Panel Finder 🔍")
        self.root.geometry("800x700")
        self.root.resizable(False, False)
        self.root.config(bg="#121212")

        self.wordlist_path = tk.StringVar()
        self.proxy_path = tk.StringVar()
        self.target_url = tk.StringVar()
        self.use_proxy = tk.BooleanVar()
        self.threads = tk.IntVar(value=10)
        self.found_admins = []

        self.is_scanning = False
        self.animation_running = False
        self.animation_label = None

        self.create_widgets()
        self.start_animation()

    def create_widgets(self):
        # === BANNER ===
        banner_frame = tk.Frame(self.root, bg="#000000", height=80)
        banner_frame.pack(fill="x", pady=10)
        banner_frame.pack_propagate(False)

        banner_label = tk.Label(
            banner_frame,
            text="▂▃▄▅▆▇█ 𝓓𝓐𝓡𝓚𝓑𝓞𝓢𝓢𝟏𝓑𝓓 █▇▆▅▄▃▂\nAdmin Panel Finder Tool",
            font=("Courier New", 14, "bold"),
            fg="#00ff00",
            bg="#000000",
            justify="center"
        )
        banner_label.pack(expand=True)

        # === INPUT FRAME ===
        input_frame = tk.Frame(self.root, bg="#1e1e1e", padx=20, pady=20)
        input_frame.pack(fill="x", padx=20, pady=10)

        # Target URL
        tk.Label(input_frame, text="🌐 Target Website (e.g., https://example.com):", bg="#1e1e1e", fg="white", font=("Arial", 10)).grid(row=0, column=0, sticky="w", pady=5)
        tk.Entry(input_frame, textvariable=self.target_url, width=50, font=("Arial", 10)).grid(row=1, column=0, columnspan=2, pady=5, sticky="ew")

        # Wordlist
        tk.Label(input_frame, text="📂 Wordlist File:", bg="#1e1e1e", fg="white", font=("Arial", 10)).grid(row=2, column=0, sticky="w", pady=5)
        tk.Entry(input_frame, textvariable=self.wordlist_path, width=40, state="readonly", font=("Arial", 10)).grid(row=3, column=0, padx=(0, 5), sticky="ew")
        tk.Button(input_frame, text="Browse", command=self.load_wordlist, bg="#006400", fg="white", font=("Arial", 9)).grid(row=3, column=1, sticky="w")

        # Proxy (Optional)
        tk.Checkbutton(input_frame, text="Use Proxy?", variable=self.use_proxy, bg="#1e1e1e", fg="cyan", selectcolor="black", font=("Arial", 10)).grid(row=4, column=0, sticky="w", pady=5)
        tk.Entry(input_frame, textvariable=self.proxy_path, width=40, state="readonly", font=("Arial", 10)).grid(row=5, column=0, padx=(0, 5), pady=5, sticky="ew")
        tk.Button(input_frame, text="Browse", command=self.load_proxy, bg="#4169e1", fg="white", font=("Arial", 9)).grid(row=5, column=1, sticky="w")

        # Threads
        tk.Label(input_frame, text="🧵 Threads:", bg="#1e1e1e", fg="white", font=("Arial", 10)).grid(row=6, column=0, sticky="w", pady=5)
        tk.Spinbox(input_frame, from_=1, to=50, textvariable=self.threads, width=10, font=("Arial", 10)).grid(row=6, column=1, sticky="w")

        input_frame.grid_columnconfigure(0, weight=1)

        # === BUTTONS ===
        btn_frame = tk.Frame(self.root, bg="#121212")
        btn_frame.pack(pady=10)

        self.start_btn = tk.Button(btn_frame, text="🚀 START SCAN", command=self.start_scan, bg="#00b300", fg="white", font=("Arial", 12, "bold"), width=15)
        self.start_btn.pack(side="left", padx=10)

        self.stop_btn = tk.Button(btn_frame, text="🛑 STOP", command=self.stop_scan, bg="#cc0000", fg="white", font=("Arial", 12, "bold"), width=15, state="disabled")
        self.stop_btn.pack(side="left", padx=10)

        # === ANIMATION LABEL ===
        self.animation_label = tk.Label(self.root, text="", font=("Courier", 10), fg="#00ff00", bg="#121212")
        self.animation_label.pack(pady=5)

        # === RESULTS FRAME ===
        result_frame = tk.Frame(self.root, bg="#1e1e1e")
        result_frame.pack(fill="both", expand=True, padx=20, pady=10)

        tk.Label(result_frame, text="🔍 Scan Results:", bg="#1e1e1e", fg="white", font=("Arial", 11, "bold")).pack(anchor="w")

        self.result_text = tk.Text(result_frame, bg="#0f0f0f", fg="#33ff33", font=("Consolas", 10), state="disabled")
        scrollbar = ttk.Scrollbar(result_frame, orient="vertical", command=self.result_text.yview)
        self.result_text.configure(yscrollcommand=scrollbar.set)
        self.result_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def start_animation(self):
        self.animation_running = True

        def animate():
            while self.animation_running:
                text = "".join(random.choices(ANIMATION_CHARS, k=60))
                self.animation_label.config(text=text)
                time.sleep(0.2)

        thread = threading.Thread(target=animate, daemon=True)
        thread.start()

    def stop_animation(self):
        self.animation_running = False
        self.animation_label.config(text="Scan completed or stopped.")

    def load_wordlist(self):
        path = filedialog.askopenfilename(title="Select Wordlist", filetypes=[("Text Files", "*.txt")])
        if path:
            self.wordlist_path.set(path)
            messagebox.showinfo("Success", f"Wordlist loaded: {os.path.basename(path)}")

    def load_proxy(self):
        path = filedialog.askopenfilename(title="Select Proxy File", filetypes=[("Text Files", "*.txt")])
        if path:
            self.proxy_path.set(path)
            messagebox.showinfo("Proxy", f"Proxy file loaded: {os.path.basename(path)}")

    def log_result(self, message, color="white"):
        self.result_text.config(state="normal")
        self.result_text.insert("end", message + "\n")
        self.result_text.see("end")
        self.result_text.config(state="disabled")

    def get_proxy(self):
        if not self.use_proxy.get() or not self.proxy_path.get():
            return None
        try:
            with open(self.proxy_path.get(), 'r') as f:
                proxies = [line.strip() for line in f if line.strip()]
            if proxies:
                proxy = random.choice(proxies)
                return {"http": f"http://{proxy}", "https": f"http://{proxy}"}
        except Exception as e:
            self.log_result(f"[!] Proxy Error: {e}", "red")
        return None

    def check_path(self, path):
        if self.is_scanning is False:
            return

        url = f"{self.target_url.get().rstrip('/')}/{path.strip('/')}"
        headers = {"User-Agent": USER_AGENT}

        try:
            proxy = self.get_proxy() if self.use_proxy.get() else None
            response = requests.get(url, headers=headers, proxies=proxy, timeout=10, allow_redirects=True)

            if response.status_code in SUCCESS_CODES:
                result = f"[+] FOUND: {url} | Status: {response.status_code}"
                self.found_admins.append(url)
                self.log_result(result, "green")
            else:
                self.log_result(f"[-] {url} -> {response.status_code}")

        except requests.exceptions.RequestException as e:
            if self.is_scanning:
                self.log_result(f"[!] Failed: {url} | {str(e)[:50]}...")

    def start_scan(self):
        if self.is_scanning:
            return

        target = self.target_url.get().strip()
        wordlist = self.wordlist_path.get()

        if not target or not wordlist:
            messagebox.showerror("Error", "Target URL and Wordlist are required!")
            return

        if not os.path.exists(wordlist):
            messagebox.showerror("Error", "Wordlist file not found!")
            return

        try:
            with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                paths = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            messagebox.showerror("Error", f"Cannot read wordlist: {e}")
            return

        if not paths:
            messagebox.showerror("Error", "Wordlist is empty!")
            return

        # Validate URL
        if not target.startswith(('http://', 'https://')):
            messagebox.showerror("Error", "URL must start with http:// or https://")
            return

        # Start scanning
        self.is_scanning = True
        self.found_admins = []
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.log_result(f"🚀 Starting scan on: {target}")
        self.log_result(f"📁 Testing {len(paths)} paths with {self.threads.get()} threads...\n")

        def run_scan():
            with ThreadPoolExecutor(max_workers=self.threads.get()) as executor:
                executor.map(self.check_path, paths)

            self.finish_scan()

        thread = threading.Thread(target=run_scan, daemon=True)
        thread.start()

    def finish_scan(self):
        self.is_scanning = False
        self.stop_animation()
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        final_msg = f"\n✅ Scan Complete! Found {len(self.found_admins)} admin panel(s)."
        self.log_result(final_msg, "yellow")
        if self.found_admins:
            for url in self.found_admins:
                self.log_result(f"🎯 {url}", "green")

    def stop_scan(self):
        if self.is_scanning:
            self.is_scanning = False
            self.stop_animation()
            self.log_result("\n🛑 Scan stopped by user.", "red")
            self.start_btn.config(state="normal")
            self.stop_btn.config(state="disabled")

    def on_closing(self):
        self.stop_scan()
        self.root.destroy()


# --- Main Execution ---
if __name__ == "__main__":
    root = tk.Tk()
    app = AdminPanelFinder(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()
