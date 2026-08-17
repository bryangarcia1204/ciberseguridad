import customtkinter as ctk
import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import queue
import configparser
from pathlib import Path
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
from PIL import Image
import sys

# Importar el agente core y el tray
from agent_core import AgentCore
from tray_icon import TrayIcon

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

if getattr(sys, 'frozen', False):
    # Modo ejecutable (PyInstaller)
    BASE_DIR = Path(sys.executable).parent
else:
    # Modo desarrollo
    BASE_DIR = Path(__file__).parent

class AgentUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Agente de Seguridad")
        self.geometry("1200x700")
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Cola para logs
        self.log_queue = queue.Queue()
        self.event_log = []  # Lista de eventos para gráficas

        # Rutas
        self.config_file = BASE_DIR / "config.ini"
        self.data_dir = BASE_DIR
        self.icon_file = BASE_DIR / "icon.png"  # Opcional

        # Cargar configuración
        self.config = configparser.ConfigParser()
        self.config.read(self.config_file)

        self.agent_core = None
        self.running = True

        # Inicializar bandeja del sistema
        self.tray = TrayIcon(self, self.icon_file if self.icon_file.exists() else None)
        threading.Thread(target=self.tray.run, daemon=True).start()

        self.create_widgets()
        self.after(100, self.update_logs)
        self.after(500, self.start_agent)

    def create_widgets(self):
        # Barra lateral izquierda
        self.sidebar = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar.pack(side="left", fill="y", padx=0, pady=0)

        # Logo o título
        logo_label = ctk.CTkLabel(self.sidebar, text="AGENTE\nSEGURIDAD", font=ctk.CTkFont(size=20, weight="bold"))
        logo_label.pack(pady=20)

        # Botones de navegación
        nav_buttons = [
            ("📊 Dashboard", self.show_dashboard),
            ("⚙️ Módulos", self.show_modules),
            ("📋 Logs", self.show_logs),
            ("🔧 Configuración", self.show_config)
        ]
        for text, command in nav_buttons:
            btn = ctk.CTkButton(self.sidebar, text=text, command=command, anchor="w", height=40)
            btn.pack(fill="x", padx=10, pady=5)

        # Contenido principal
        self.main_content = ctk.CTkFrame(self)
        self.main_content.pack(side="right", fill="both", expand=True, padx=10, pady=10)

        # Inicializar vistas
        self.dashboard_frame = ctk.CTkFrame(self.main_content)
        self.modules_frame = ctk.CTkFrame(self.main_content)
        self.logs_frame = ctk.CTkFrame(self.main_content)
        self.config_frame = ctk.CTkFrame(self.main_content)

        self.create_dashboard()
        self.create_modules()
        self.create_logs()
        self.create_config()

        # Mostrar dashboard por defecto
        self.show_dashboard()

    def create_dashboard(self):
        # Título
        ctk.CTkLabel(self.dashboard_frame, text="Dashboard", font=ctk.CTkFont(size=24, weight="bold")).pack(pady=10)

        # Tarjetas de estado
        cards_frame = ctk.CTkFrame(self.dashboard_frame)
        cards_frame.pack(fill="x", padx=20, pady=10)

        # Conectado/desconectado
        self.status_card = ctk.CTkFrame(cards_frame, width=200, height=100)
        self.status_card.pack(side="left", padx=10, pady=10, expand=True, fill="both")
        ctk.CTkLabel(self.status_card, text="Estado", font=ctk.CTkFont(size=14)).pack(pady=5)
        self.status_value = ctk.CTkLabel(self.status_card, text="Desconectado", font=ctk.CTkFont(size=18, weight="bold"), text_color="red")
        self.status_value.pack()

        # Módulos activos
        self.modules_card = ctk.CTkFrame(cards_frame, width=200, height=100)
        self.modules_card.pack(side="left", padx=10, pady=10, expand=True, fill="both")
        ctk.CTkLabel(self.modules_card, text="Módulos activos", font=ctk.CTkFont(size=14)).pack(pady=5)
        self.modules_active = ctk.CTkLabel(self.modules_card, text="0", font=ctk.CTkFont(size=18, weight="bold"))
        self.modules_active.pack()

        # Eventos por minuto (gráfica simulada)
        self.events_card = ctk.CTkFrame(cards_frame, width=200, height=100)
        self.events_card.pack(side="left", padx=10, pady=10, expand=True, fill="both")
        ctk.CTkLabel(self.events_card, text="Eventos/min", font=ctk.CTkFont(size=14)).pack(pady=5)
        self.events_label = ctk.CTkLabel(self.events_card, text="0", font=ctk.CTkFont(size=18, weight="bold"))
        self.events_label.pack()

        # Gráfica de eventos (simulada con matplotlib)
        graph_frame = ctk.CTkFrame(self.dashboard_frame)
        graph_frame.pack(fill="both", expand=True, padx=20, pady=20)

        fig, ax = plt.subplots(figsize=(8, 3), dpi=100)
        ax.set_facecolor('#2b2b2b')
        fig.patch.set_facecolor('#2b2b2b')
        ax.spines['bottom'].set_color('white')
        ax.spines['left'].set_color('white')
        ax.tick_params(colors='white')
        ax.set_ylabel('Eventos', color='white')
        ax.set_xlabel('Tiempo', color='white')

        self.canvas = FigureCanvasTkAgg(fig, master=graph_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)
        self.ax = ax
        self.line, = ax.plot([], [], color='green', linewidth=2)

        # Actualizar gráfica periódicamente
        self.update_graph()

    def create_modules(self):
        ctk.CTkLabel(self.modules_frame, text="Módulos", font=ctk.CTkFont(size=24, weight="bold")).pack(pady=10)

        # Frame principal con dos columnas
        self.modules_main = ctk.CTkFrame(self.modules_frame)
        self.modules_main.pack(fill="both", expand=True, padx=10, pady=10)

        # Columna izquierda: lista de módulos
        self.modules_list_frame = ctk.CTkFrame(self.modules_main, width=200)
        self.modules_list_frame.pack(side="left", fill="y", padx=5, pady=5)
        self.modules_list_frame.pack_propagate(False)

        ctk.CTkLabel(self.modules_list_frame, text="Módulos disponibles", font=ctk.CTkFont(size=14, weight="bold")).pack(pady=5)

        # Canvas con scroll para la lista
        self.modules_canvas = ctk.CTkCanvas(self.modules_list_frame, bg="#2b2b2b", highlightthickness=0)
        self.modules_canvas.pack(side="left", fill="both", expand=True)

        self.modules_scrollbar = ctk.CTkScrollbar(self.modules_list_frame, orientation="vertical", command=self.modules_canvas.yview)
        self.modules_scrollbar.pack(side="right", fill="y")

        self.modules_canvas.configure(yscrollcommand=self.modules_scrollbar.set)
        self.modules_canvas.bind('<Configure>', lambda e: self.modules_canvas.configure(scrollregion=self.modules_canvas.bbox("all")))

        self.modules_inner_frame = ctk.CTkFrame(self.modules_canvas)
        self.modules_canvas.create_window((0, 0), window=self.modules_inner_frame, anchor="nw")

        # Diccionario para guardar referencias de cada módulo en la lista
        self.modules_list_items = {}  # nombre -> (frame, status_label)

        # Columna derecha: detalles del módulo seleccionado
        self.module_detail_frame = ctk.CTkFrame(self.modules_main)
        self.module_detail_frame.pack(side="right", fill="both", expand=True, padx=5, pady=5)

        # Título del módulo seleccionado
        self.selected_module_label = ctk.CTkLabel(self.module_detail_frame, text="Selecciona un módulo", font=ctk.CTkFont(size=16))
        self.selected_module_label.pack(pady=5)

        # Pestañas dentro del detalle
        self.detail_tabview = ctk.CTkTabview(self.module_detail_frame)
        self.detail_tabview.pack(fill="both", expand=True, padx=5, pady=5)

        self.tab_logs_detail = self.detail_tabview.add("Logs")
        self.tab_config_detail = self.detail_tabview.add("Configuración")

        # Área de logs (con scroll)
        from tkinter import scrolledtext
        self.logs_detail_text = scrolledtext.ScrolledText(self.tab_logs_detail, wrap="word", bg="#2b2b2b", fg="#ffffff", height=15)
        self.logs_detail_text.pack(fill="both", expand=True)

        # Área de configuración
        self.config_detail_text = ctk.CTkTextbox(self.tab_config_detail, height=200)
        self.config_detail_text.pack(fill="both", expand=True)

        # Botones de acción
        self.action_frame = ctk.CTkFrame(self.module_detail_frame)
        self.action_frame.pack(fill="x", pady=5)

        self.start_btn = ctk.CTkButton(self.action_frame, text="Iniciar", state="disabled", command=self.start_selected_module)
        self.start_btn.pack(side="left", padx=5)

        self.stop_btn = ctk.CTkButton(self.action_frame, text="Detener", state="disabled", command=self.stop_selected_module)
        self.stop_btn.pack(side="left", padx=5)

        self.configure_btn = ctk.CTkButton(self.action_frame, text="Configurar", state="disabled", command=self.configure_selected_module)
        self.configure_btn.pack(side="left", padx=5)

        self.refresh_logs_btn = ctk.CTkButton(self.action_frame, text="Actualizar logs", state="disabled", command=self.refresh_selected_module_logs)
        self.refresh_logs_btn.pack(side="left", padx=5)

        self.selected_module = None

    def create_logs(self):
        ctk.CTkLabel(self.logs_frame, text="Logs", font=ctk.CTkFont(size=24, weight="bold")).pack(pady=10)

        self.log_text = scrolledtext.ScrolledText(self.logs_frame, wrap=tk.WORD, bg="#2b2b2b", fg="#ffffff", insertbackground='white')
        self.log_text.pack(fill="both", expand=True, padx=20, pady=10)

    def create_config(self):
        ctk.CTkLabel(self.config_frame, text="Configuración", font=ctk.CTkFont(size=24, weight="bold")).pack(pady=10)

        # Formulario de configuración
        config_inner = ctk.CTkFrame(self.config_frame)
        config_inner.pack(fill="both", expand=True, padx=20, pady=10)

        row = 0
        ctk.CTkLabel(config_inner, text="URL del servidor:").grid(row=row, column=0, sticky="w", pady=5, padx=5)
        self.url_entry = ctk.CTkEntry(config_inner, width=400)
        self.url_entry.grid(row=row, column=1, pady=5, padx=5)
        self.url_entry.insert(0, self.config.get("server", "url", fallback=""))
        row += 1

        ctk.CTkLabel(config_inner, text="Nombre del agente:").grid(row=row, column=0, sticky="w", pady=5, padx=5)
        self.name_entry = ctk.CTkEntry(config_inner, width=400)
        self.name_entry.grid(row=row, column=1, pady=5, padx=5)
        self.name_entry.insert(0, self.config.get("server", "agent_name", fallback=""))
        row += 1

        self.verify_ssl_var = tk.BooleanVar(value=self.config.getboolean("server", "verify_ssl", fallback=False))
        self.verify_ssl_check = ctk.CTkCheckBox(config_inner, text="Verificar SSL", variable=self.verify_ssl_var)
        self.verify_ssl_check.grid(row=row, column=0, columnspan=2, sticky="w", pady=5, padx=5)
        row += 1

        self.save_config_btn = ctk.CTkButton(config_inner, text="Guardar configuración", command=self.save_config)
        self.save_config_btn.grid(row=row, column=0, columnspan=2, pady=10)
    
    def select_module(self, module_name):
        self.selected_module = module_name
        self.selected_module_label.configure(text=module_name)
        # Habilitar botones
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="normal")
        self.configure_btn.configure(state="normal")
        self.refresh_logs_btn.configure(state="normal")
        # Cargar logs y configuración
        self.refresh_selected_module_logs()
        self.show_module_config()

    def refresh_selected_module_logs(self):
        if not self.selected_module or not self.agent_core:
            return
        logs = self.agent_core.get_module_logs(self.selected_module, limit=50)
        self.logs_detail_text.delete(1.0, tk.END)
        for log in logs:
            self.logs_detail_text.insert(tk.END, f"[{log['timestamp']}] {log['level']}: {log['message']}\n")
        self.logs_detail_text.see(tk.END)

    def show_module_config(self):
        if not self.selected_module or not self.agent_core:
            return
        config = self.agent_core.get_module_config(self.selected_module)
        import json
        self.config_detail_text.delete(1.0, tk.END)
        self.config_detail_text.insert(tk.END, json.dumps(config, indent=2))

    def start_selected_module(self):
        if self.selected_module:
            self.agent_core.start_module(self.selected_module)

    def stop_selected_module(self):
        if self.selected_module:
            self.agent_core.stop_module(self.selected_module)

    def configure_selected_module(self):
        # Puedes implementar un diálogo de edición, por ahora solo mensaje
        self.log_callback(f"Configurar {self.selected_module} (pendiente de implementación)")

    def show_dashboard(self):
        self.hide_all_frames()
        self.dashboard_frame.pack(fill="both", expand=True)

    def show_modules(self):
        self.hide_all_frames()
        self.modules_frame.pack(fill="both", expand=True)

    def show_logs(self):
        self.hide_all_frames()
        self.logs_frame.pack(fill="both", expand=True)

    def show_config(self):
        self.hide_all_frames()
        self.config_frame.pack(fill="both", expand=True)

    def hide_all_frames(self):
        for frame in [self.dashboard_frame, self.modules_frame, self.logs_frame, self.config_frame]:
            frame.pack_forget()

    def log_callback(self, message):
        self.log_queue.put(message)

    def update_logs(self):
        while not self.log_queue.empty():
            msg = self.log_queue.get()
            self.log_text.insert(tk.END, msg + "\n")
            self.log_text.see(tk.END)
            self.event_log.append(msg)  # Para gráficas
        self.after(100, self.update_logs)

    def start_agent(self):
        self.agent_core = AgentCore(self.config_file, self.data_dir, log_callback=self.log_callback)
        threading.Thread(target=self.agent_core.start, daemon=True).start()
        self.status_value.configure(text="Iniciando...", text_color="orange")
        self.after(2000, self.check_agent_status)

    def check_agent_status(self):
        if self.agent_core and self.agent_core.client:
            if self.agent_core.client.ws:
                self.status_value.configure(text="Conectado", text_color="green")
                self.update_modules_list()
            else:
                self.status_value.configure(text="Conectando...", text_color="orange")
        self.after(2000, self.check_agent_status)

    def update_modules_list(self):
        if not self.agent_core:
            return
        status = self.agent_core.get_modules_status()

        # Actualizar contador de módulos activos (para el dashboard)
        active_count = sum(1 for v in status.values() if v)
        self.modules_active.configure(text=str(active_count))

        # Crear elementos en la lista para módulos nuevos
        for name, running in status.items():
            if name not in self.modules_list_items:
                frame = ctk.CTkFrame(self.modules_inner_frame)
                frame.pack(fill="x", padx=2, pady=2)

                # Hacer clic en el frame o en la etiqueta selecciona el módulo
                frame.bind("<Button-1>", lambda e, n=name: self.select_module(n))

                label = ctk.CTkLabel(frame, text=name, width=150, anchor="w")
                label.pack(side="left", padx=5)
                label.bind("<Button-1>", lambda e, n=name: self.select_module(n))

                status_label = ctk.CTkLabel(frame, text="Running" if running else "Stopped",
                                            text_color="green" if running else "red")
                status_label.pack(side="right", padx=5)
                status_label.bind("<Button-1>", lambda e, n=name: self.select_module(n))

                self.modules_list_items[name] = (frame, status_label)
            else:
                # Actualizar estado
                frame, status_label = self.modules_list_items[name]
                status_label.configure(text="Running" if running else "Stopped",
                                    text_color="green" if running else "red")

    def start_module(self, name):
        if self.agent_core:
            self.agent_core.start_module(name)

    def stop_module(self, name):
        if self.agent_core:
            self.agent_core.stop_module(name)

    def update_graph(self):
        # Simular datos de eventos (últimos 20 puntos)
        x = list(range(len(self.event_log[-20:])))
        y = [len(msg) for msg in self.event_log[-20:]]  # Ejemplo: longitud del mensaje como "eventos"
        self.line.set_data(x, y)
        self.ax.relim()
        self.ax.autoscale_view()
        self.canvas.draw()
        self.after(2000, self.update_graph)

    def save_config(self):
        self.config["server"]["url"] = self.url_entry.get()
        self.config["server"]["agent_name"] = self.name_entry.get()
        self.config["server"]["verify_ssl"] = str(self.verify_ssl_var.get())
        with open(self.config_file, "w") as f:
            self.config.write(f)
        self.log_callback("Configuración guardada. Reinicia el agente para aplicar cambios.")

    def reconnect(self):
        self.log_callback("Reconectando...")
        self.start_agent()

    def on_closing(self):
        if messagebox.askokcancel("Salir", "¿Minimizar a la bandeja?"):
            self.withdraw()  # Ocultar ventana, no cerrar
        else:
            self.running = False
            if self.agent_core:
                # Intentar detener el agente
                pass
            self.quit()
            self.tray.icon.stop()

if __name__ == "__main__":
    app = AgentUI()
    app.mainloop()