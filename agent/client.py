import asyncio
import websockets
import json
import socket
import httpx
import ssl
from pathlib import Path
import configparser
import keyring
import hashlib
import sys
from datetime import datetime

SERVICE_NAME = "CiberseguridadAgent"

class AgentClient:
    def __init__(self, config_file="config.ini", data_dir=None, log_callback=None):
        self.log_callback = log_callback
        self.data_dir = Path(data_dir) if data_dir else Path.cwd()
        self.config = configparser.ConfigParser()
        self.config.read(config_file)
        self._log("Secciones encontradas: " + str(self.config.sections()))
        self.server_url = self.config["server"]["url"].rstrip("/")
        self.agent_name = self.config["server"].get("agent_name", socket.gethostname())
        self.verify_ssl = self.config.getboolean("server", "verify_ssl", fallback=False)
        self.token = self._load_token()
        self.ws = None
        self.modules = {}
        self.module_logs = {}  # módulo -> lista de logs

    def _log(self, message):
        if self.log_callback:
            self.log_callback(message)
        else:
            print(message)

    def _load_token(self):
        return keyring.get_password(SERVICE_NAME, self.agent_name)

    def _save_token(self, token):
        keyring.set_password(SERVICE_NAME, self.agent_name, token)

    def _delete_token(self):
        try:
            keyring.delete_password(SERVICE_NAME, self.agent_name)
            self.token = None
            self._log("Token eliminado de keyring")
        except:
            pass

    def _get_self_hash(self):
        if getattr(sys, 'frozen', False):
            try:
                with open(sys.executable, 'rb') as f:
                    return hashlib.sha256(f.read()).hexdigest()
            except Exception as e:
                self._log(f"Error al calcular hash: {e}")
        return None

    async def register(self):
        hostname = socket.gethostname()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
        except:
            ip = "0.0.0.0"

        agent_hash = self._get_self_hash()
        params = {"name": self.agent_name, "hostname": hostname, "ip": ip}
        if agent_hash:
            params["hash"] = agent_hash

        url = f"{self.server_url}/agents/register"
        self._log(f"Intentando registrar en: {url}")
        async with httpx.AsyncClient(verify=self.verify_ssl) as client:
            resp = await client.post(url, params=params)
            if resp.status_code == 200:
                data = resp.json()
                self.token = data["token"]
                self._save_token(self.token)
                self._log("Agente registrado correctamente")
                return True
            else:
                self._log(f"Error al registrar: {resp.text}")
                return False

    async def connect_websocket(self):
        if self.server_url.startswith("https"):
            ws_url = "wss" + self.server_url[5:] + "/agents/ws"
        else:
            ws_url = "ws" + self.server_url[4:] + "/agents/ws"

        ssl_context = None
        if ws_url.startswith("wss") and not self.verify_ssl:
            ssl_context = ssl._create_unverified_context()

        while True:
            try:
                async with websockets.connect(ws_url, ssl=ssl_context) as websocket:
                    # Enviar token
                    await websocket.send(json.dumps({"token": self.token}))
                    self.ws = websocket
                    self._log("Conectado al servidor central")
                    async for message in websocket:
                        await self.handle_command(json.loads(message))
            except websockets.exceptions.InvalidStatusCode as e:
                self._log(f"Error de conexión (HTTP {e.status_code}), probablemente token inválido")
                if e.status_code == 403:
                    self._delete_token()
                    self._log("Token eliminado, reintentando registro...")
                    if await self.register():
                        continue
                    else:
                        self._log("No se pudo registrar, esperando 30s...")
                        await asyncio.sleep(30)
                        continue
                else:
                    self._log(f"Reintentando en 5s...")
                    await asyncio.sleep(5)
                    continue
            except websockets.exceptions.ConnectionClosed as e:
                if e.code == 1008:
                    self._log("Conexión cerrada por token inválido (código 1008), eliminando token")
                    self._delete_token()
                    self._log("Reintentando registro...")
                    if await self.register():
                        continue
                    else:
                        self._log("No se pudo registrar, esperando 30s...")
                        await asyncio.sleep(30)
                        continue
                else:
                    self._log(f"Conexión perdida (código {e.code}): {e.reason}. Reintentando en 5s...")
                    await asyncio.sleep(5)
                    continue
            except (ConnectionRefusedError, OSError) as e:
                self._log(f"No se pudo conectar al servidor: {e}. Reintentando en 5s...")
                await asyncio.sleep(5)
                continue

    async def handle_command(self, cmd):
        action = cmd.get("action")
        module_name = cmd.get("module")
        if action == "start":
            if module_name in self.modules:
                self.modules[module_name].start()
                self._log(f"Módulo {module_name} iniciado por comando")
        elif action == "stop":
            if module_name in self.modules:
                await self.modules[module_name].stop()
                self._log(f"Módulo {module_name} detenido por comando")
        elif action == "configure":
            if module_name in self.modules:
                self.modules[module_name].config.update(cmd.get("config", {}))
                self._log(f"Módulo {module_name} reconfigurado")

    async def send_event(self, event_type, level, module, message, data=None):
        if self.ws:
            try:
                await self.ws.send(json.dumps({
                    "type": event_type,
                    "level": level,
                    "module": module,
                    "message": message,
                    "data": data or {}
                }))
            except:
                pass

        if module not in self.module_logs:
            self.module_logs[module] = []
        self.module_logs[module].append({
            'timestamp': datetime.now().strftime("%H:%M:%S"),
            'level': level,
            'message': message
        })
        # Mantener últimos 100
        if len(self.module_logs[module]) > 100:
            self.module_logs[module].pop(0)

    def get_module_logs(self, module_name, limit=50):
        return self.module_logs.get(module_name, [])[-limit:]

    async def run(self):
        if not self.token:
            if not await self.register():
                return
        await self.connect_websocket()