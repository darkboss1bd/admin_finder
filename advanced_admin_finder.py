import tkinter as tk
from tkinter import ttk, messagebox
import requests
import threading
import time
import random

# Common admin panel paths
COMMON_ADMIN_PATHS = [
    'admin/', 'administrator/', 'admin1/', 'admin2/', 'admin3/', 'admin4/', 'admin5/',
    'usuarios/', 'usuario/', 'moderator/', 'webadmin/', 'adminarea/', 'bb-admin/',
    'adminLogin/', 'admin_login/', 'panel-administracion/', 'instadmin/',
    'memberadmin/', 'administratorlogin/', 'adm/', 'admin/account.php',
    'admin/index.php', 'admin/login.php', 'admin/admin.php',
    'admin_area/', 'admin_control/', 'admincp/', 'adminpanel/', 'admin1.html',
    'admin2.html', 'admin3.html', 'admin4.html', 'admin5.html',
    'admin/account.html', 'admin/index.html', 'admin/login.html', 'admin/admin.html',
    'admin/home.html', 'admin/control.html', 'admin/cp', 'cp', 'administrator/',
    'login.php', 'modelsearch/login.php', 'moderator.php', 'moderator/login.php',
    'moderator/admin.php', 'control.php', 'account.php', 'admin/account.html',
    'adminpanel.html', 'webadmin.html', 'webadmin/index.html', 'webadmin/admin.html',
    'webadmin/login.html', 'admin/admin_login.html', 'admin_login.html',
    'panel-administracion/login.html', 'pages/admin/admin-login.html',
    'admin/admin-login.html', 'admin-login.html', 'bb-admin/index.html',
    'bb-admin/login.html', 'bb-admin/admin.html', 'admin/home.html',
    'login.html', 'modelsearch/login.html', 'moderator.html',
    'moderator/login.html', 'moderator/admin.html', 'user.html',
    'account.html', 'control.html', 'admincontrol.html', 'admin_login.html',
    'panel-administracion/admin.html', 'panel-administracion/login.html',
    'admin/cp.php', 'cp.php', 'administrator/account.php', 'administrator.php',
    'nsw/admin/login.php', 'webadmin/login.php', 'admin/admin_login.php',
    'admin_login.php', 'administrator/account.php', 'administrator/login.php',
    'administrator/control.php', 'adminarea/admin.html', 'adminarea/login.html',
    'webadmin/admin.php', 'webadmin/index.php'
]

# Hacker ASCII Art (Banner)
BANNER = r"""
  ___ _   _ ____  ____    _  _____ ___ ___  _   _ 
 / _ \ | | / ___||  _ \  / \|_   _|_ _/ _ \| \ | |
| | | | | | \___ \| | | |/ _ \ | |  | | | | |  \| |
| |_| | |_| |___) | |_| / ___ \| |  | | |_| | |\  |
 \__\_\\___/|____/|____/_/   \_\_| |___\___/|_| \_|
                                                   
       [+] DarkBoss1BD - Admin Panel Finder [+]
       [+] Advanced Tool with Hacker Style UI [+]
"""

# Typing effect for animation
def animate_text(widget, text, delay=50):
    widget.config(state=tk.NORMAL)
    widget.delete(1.0, tk.END)
    def type_char(i=0):
        if i < len(text):
            widget.insert(tk.END, text[i])
            widget.see(tk.END)
            widget.after(delay, type_char, i + 1)
        else:
            widget.config(state=tk.DISABLED)
    type_char()

# Main App Class
class AdminPanelFinder:
    def __init__(self, root):
        self.root = root
        self.root.title("DarkBoss1BD - Admin Panel Finder")
        self.root.geometry("800x600")
        self.root.resizable(False, False)
        self.root.configure(bg="#0e0e0e")

        # Style
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TLabel", background="#0e0e0e", foreground="#00ff00", font=("Consolas", 10))
        style.configure("TButton", background="#1a1a1a", foreground="#00ff00", font=("Consolas", 10))
        style.map("TButton", background=[('active', '#2a2a2a')])

        # Banner Label
        self.banner_text = tk.Text(root, bg="#0e0e0e", fg="#00ff00", font=("Courier", 10), wrap=tk.NONE, height=12, relief="flat")
        self.banner_text.pack(pady=10)
        animate_text(self.banner_text, BANNER, delay=30)

        # URL Input
        self.url_label = ttk.Label(root, text="Enter Website URL (e.g., http://example.com):")
        self.url_label.pack(pady=5)

        self.url_entry = ttk.Entry(root, width=60, font=("Consolas", 10))
        self.url_entry.pack(pady=5)

        # Start Button
        self.start_btn = ttk.Button(root, text="🔍 Start Scan", command=self.start_scan)
        self.start_btn.pack(pady=10)

        # Progress Bar
        self.progress = ttk.Progressbar(root, orient="horizontal", length=500, mode="determinate")
        self.progress.pack(pady=10)

        # Result Text Box
        self.result_frame = tk.Frame(root, bg="#0e0e0e")
        self.result_frame.pack(pady=10, fill=tk.BOTH, expand=True)

        self.result_text = tk.Text(self.result_frame, bg="#111", fg="#00ff00", font=("Consolas", 10), wrap=tk.WORD, state=tk.DISABLED)
        self.scrollbar = tk.Scrollbar(self.result_frame, command=self.result_text.yview, bg="#333")
        self.result_text.config(yscrollcommand=self.scrollbar.set)
        self.result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Status Label
        self.status_label = ttk.Label(root, text="Ready to scan...", font=("Consolas", 9))
        self.status_label.pack(pady=5)

    def start_scan(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Input Error", "Please enter a valid URL!")
            return

        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url

        self.url_entry.delete(0, tk.END)
        self.url_entry.insert(0, url)

        # Clear previous results
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)
        self.result_text.config(state=tk.DISABLED)

        # Run scan in a separate thread
        self.scan_thread = threading.Thread(target=self.scan_admin_panel, args=(url,), daemon=True)
        self.scan_thread.start()

    def scan_admin_panel(self, base_url):
        self.root.after(0, lambda: self.update_status("Starting scan..."))
        found_panels = []
        total = len(COMMON_ADMIN_PATHS)
        checked = 0

        for path in COMMON_ADMIN_PATHS:
            try:
                url = f"{base_url.rstrip('/')}/{path}"
                response = requests.get(url, timeout=5, headers={"User-Agent": "DarkBoss1BD Scanner"})
                if response.status_code == 200:
                    found_panels.append(url)
                    self.root.after(0, lambda u=url: self.append_result(f"[+] FOUND: {u}\n"))
                elif response.status_code == 403:
                    self.root.after(0, lambda u=url: self.append_result(f"[~] Forbidden: {u}\n"))
            except requests.exceptions.RequestException:
                pass  # Ignore connection errors
            except Exception as e:
                print(e)

            checked += 1
            progress = (checked / total) * 100
            self.root.after(0, lambda p=progress: self.progress['value'] = p)
            time.sleep(0.05)  # Simulate realistic delay

        # Final Result
        self.root.after(0, lambda: self.update_status(f"Scan complete! Found {len(found_panels)} admin panels."))
        if not found_panels:
            self.append_result("[!] No admin panels found.\n")

    def append_result(self, text):
        self.result_text.config(state=tk.NORMAL)
        self.result_text.insert(tk.END, text)
        self.result_text.see(tk.END)
        self.result_text.config(state=tk.DISABLED)

    def update_status(self, text):
        self.status_label.config(text=text)

# Run the app
if __name__ == "__main__":
    root = tk.Tk()
    app = AdminPanelFinder(root)
    root.mainloop()