import pystray
from PIL import Image, ImageDraw
import threading
import queue
from pathlib import Path
import sys

class TrayIcon:
    def __init__(self, app, icon_path=None):
        self.app = app
        self.icon = None
        self.queue = queue.Queue()
        self.create_icon(icon_path)

    def create_icon(self, icon_path):
        if icon_path and Path(icon_path).exists():
            image = Image.open(icon_path)
        else:
            # Crear un icono simple por defecto
            image = Image.new('RGB', (64, 64), color='green')
            draw = ImageDraw.Draw(image)
            draw.rectangle((16, 16, 48, 48), fill='white')
        menu = pystray.Menu(
            pystray.MenuItem("Abrir", self.show_window),
            pystray.MenuItem("Salir", self.quit_app)
        )
        self.icon = pystray.Icon("agent", image, "Agente de Seguridad", menu)

    def show_window(self):
        self.app.deiconify()
        self.app.lift()

    def quit_app(self):
        self.app.quit()
        self.icon.stop()

    def run(self):
        self.icon.run()

    def update_status(self, status):
        """Actualiza el icono según el estado (conectado/desconectado)."""
        # Podríamos cambiar el color del icono dinámicamente, pero es complejo.
        # Por simplicidad, no se implementa.
        pass