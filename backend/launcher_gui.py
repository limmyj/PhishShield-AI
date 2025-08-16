import os
import sys
import requests
import threading
import tkinter as tk
import multiprocessing
import webbrowser

from datetime import datetime
from waitress import serve
from PIL import Image, ImageTk
from tkinter import ttk, scrolledtext, messagebox
from pystray import Icon, Menu, MenuItem as item
from plyer import notification
from app import app as flask_app

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

def run_backend():
    try:
        serve(flask_app, host='127.0.0.1', port=5000)
    except Exception as e:
        print("Backend failed to launch:", e)

class PhishShieldLauncher(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PhishShield AI Launcher")
        self.geometry("600x600")
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self.hide_to_tray)

        self.backend_process = None
        self.tray_icon = None
        self.dark_mode = tk.BooleanVar(value=False)

        self.create_widgets()
        self.apply_theme()

    def create_widgets(self):
        logo_path = resource_path("icon.png")
        try:
            img = Image.open(logo_path).resize((100, 100))
            self.logo_img = ImageTk.PhotoImage(img)
            tk.Label(self, image=self.logo_img).pack(pady=(20, 5))
        except Exception as e:
            print("Failed to load logo image:", e)

        tk.Label(self, text="PhishShield AI", font=("Segoe UI", 20, "bold")).pack()

        status_frame = tk.Frame(self)
        self.status_label = tk.Label(status_frame, text="Backend stopped.", font=("Segoe UI", 12))
        self.status_label.grid(row=0, column=0)
        self.status_dot = tk.Canvas(status_frame, width=10, height=10, highlightthickness=0)
        self.dot = self.status_dot.create_oval(2, 2, 10, 10, fill="red")
        self.status_dot.grid(row=0, column=1, padx=4)
        status_frame.pack(pady=10)

        self.tooltip_label = tk.Label(self, text="", font=("Segoe UI", 9, "italic"), bd=0)
        self.tooltip_label.pack()

        self.status_dot.bind("<Enter>", lambda e: self.show_status_tooltip())
        self.status_dot.bind("<Leave>", lambda e: self.clear_status_tooltip())

        self.url_display = tk.Label(self, text="", font=("Segoe UI", 10))
        self.url_display.pack()

        self.progress = ttk.Progressbar(self, mode="indeterminate", length=300)
        self.progress.pack(pady=(0, 10))
        self.progress.pack_forget()

        self.start_button = ttk.Button(self, text="🚀 Launch", command=self.start_backend)
        self.start_button.pack(pady=5)

        self.stop_button = ttk.Button(self, text="🛑 Stop", command=self.stop_backend, state='disabled')
        self.stop_button.pack(pady=5)

        self.toggle_button = ttk.Button(self, text="Show Logs", command=self.toggle_logs)
        self.toggle_button.pack(pady=5)

        self.autoscroll = tk.BooleanVar(value=True)
        tk.Checkbutton(self, text="Auto-scroll Logs", variable=self.autoscroll).pack()

        ttk.Checkbutton(self, text="🌙 Dark Mode", variable=self.dark_mode, command=self.apply_theme).pack(pady=5)

        self.log_output = scrolledtext.ScrolledText(self, height=15, width=70, state='disabled',
                                                    font=("Consolas", 10))
        self.log_output.pack(pady=10)
        self.log_output.pack_forget()

        ttk.Button(self, text="Help", command=self.show_help).pack(pady=(5, 0))

        tk.Label(self, text="v1.0.0 | by Lim Yee Jiun", font=("Segoe UI", 8)).pack(side="bottom", pady=5)

    def apply_theme(self):
        is_dark = self.dark_mode.get()
        theme = {
            "bg": "#1e1e1e" if is_dark else "#f4f4f4",
            "fg": "#f4f4f4" if is_dark else "#222222",
            "text": "#dddddd" if is_dark else "#222222",
            "entry_bg": "#2e2e2e" if is_dark else "#ffffff",
            "entry_fg": "#eeeeee" if is_dark else "#222222",
            "accent": "#444" if is_dark else "#ccc",
            "tooltip_fg": "#aaa" if is_dark else "#888",
            "link": "#4fa3ff" if is_dark else "#0066cc"
        }

        self.configure(bg=theme["bg"])
        self.tooltip_label.configure(bg=theme["bg"], fg=theme["tooltip_fg"])
        self.url_display.configure(bg=theme["bg"], fg=theme["link"])
        self.status_label.configure(bg=theme["bg"], fg=theme["text"])
        self.status_dot.configure(bg=theme["bg"])
        self.log_output.configure(bg=theme["entry_bg"], fg=theme["entry_fg"], insertbackground=theme["entry_fg"])

        for widget in self.winfo_children():
            try:
                widget.configure(bg=theme["bg"], fg=theme["fg"])
            except:
                pass

        style = ttk.Style()
        style.theme_use("default")
        style.configure("TButton", background=theme["accent"], foreground=theme["fg"])
        style.configure("TCheckbutton", background=theme["bg"], foreground=theme["fg"])
        style.configure("TLabel", background=theme["bg"], foreground=theme["fg"])

    def toggle_logs(self):
        if self.log_output.winfo_viewable():
            self.log_output.pack_forget()
            self.toggle_button.config(text="Show Logs")
        else:
            self.log_output.pack(pady=10)
            self.toggle_button.config(text="Hide Logs")

    def start_backend(self):
        if self.backend_process and self.backend_process.is_alive():
            return
        self.append_log("🚀 Starting Flask backend...\n")
        self.progress.pack()
        self.progress.start()
        self.status_label.config(text="Starting backend, please wait...")
        self.status_dot.itemconfig(self.dot, fill="orange")
        self.backend_process = multiprocessing.Process(target=run_backend)
        self.backend_process.start()
        self.after(2000, self.backend_ready)

    def backend_ready(self):
        self.progress.stop()
        self.progress.pack_forget()

        def poll():
            try:
                r = requests.post("http://127.0.0.1:5000/api/check", json={"email_text": "test"})
                if r.status_code == 503:
                    self.status_label.config(text="Initializing backend... please wait")
                    self.status_dot.itemconfig(self.dot, fill="orange")
                    self.after(1000, poll)
                else:
                    self.status_label.config(text="✅ Ready for analysis")
                    self.status_dot.itemconfig(self.dot, fill="green")
                    self.url_display.config(text="http://127.0.0.1:5000")
                    self.append_log("✅ Backend is fully ready.\n")
                    self.start_button.config(state='disabled')
                    self.stop_button.config(state='normal')
            except:
                self.status_label.config(text="Waiting for backend response...")
                self.status_dot.itemconfig(self.dot, fill="orange")
                self.after(1000, poll)

        poll()

    def stop_backend(self):
        if self.backend_process and self.backend_process.is_alive():
            self.backend_process.terminate()
            self.backend_process.join()
            self.append_log("🛑 Backend has been stopped.\n")
            self.status_label.config(text="Backend stopped.")
            self.status_dot.itemconfig(self.dot, fill="red")
            self.url_display.config(text="")
            self.start_button.config(state='normal')
            self.stop_button.config(state='disabled')

    def append_log(self, message):
        timestamp = datetime.now().strftime("[%H:%M:%S] ")
        self.log_output.configure(state='normal')
        self.log_output.insert(tk.END, timestamp + message)
        if self.autoscroll.get():
            self.log_output.see(tk.END)
        self.log_output.configure(state='disabled')

    def show_status_tooltip(self):
        dot_color = self.status_dot.itemcget(self.dot, "fill")
        msg = {
            "red": "Backend not running",
            "orange": "Backend starting...",
            "green": "Backend ready"
        }.get(dot_color, "Status unknown")
        self.tooltip_label.config(text=f"🛈 {msg}")

    def clear_status_tooltip(self):
        self.tooltip_label.config(text="")

    def show_help(self):
        messagebox.showinfo("Help", "• Click Launch to start backend.\n• Click Stop to shut down.\n• View logs to monitor activity.\n• Right-click tray icon to exit.")

    def hide_to_tray(self):
        self.withdraw()
        icon_path = resource_path("icon.png")
        try:
            icon_img = Image.open(icon_path).resize((64, 64))
        except Exception as e:
            print("⚠️ Failed to load tray icon:", e)
            return

        def show_window(icon, item):
            self.deiconify()

        def exit_app(icon, item):
            if messagebox.askyesno("Exit", "Are you sure you want to quit?"):
                icon.stop()
                self.stop_backend()
                self.destroy()

        self.tray_icon = Icon("PhishShield AI", icon_img, menu=Menu(item('Restore', show_window), item('Exit', exit_app)))
        notification.notify(title='PhishShield AI', message='Running in system tray. Right-click to exit.', timeout=3)
        threading.Thread(target=self.tray_icon.run, daemon=True).start()


if __name__ == "__main__":
    multiprocessing.freeze_support()
    app = PhishShieldLauncher()
    app.mainloop()