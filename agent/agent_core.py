import asyncio
import threading
import json
import sys
import pkgutil
import importlib
from pathlib import Path
from client import AgentClient
from modules.module_base import Module

class AgentCore:
    def __init__(self, config_path, data_dir, log_callback=None):
        self.config_path = config_path
        self.data_dir = data_dir
        self.log_callback = log_callback
        self.client = None
        self.loop = None
        self.thread = None
        self.running = False
        self.modules = {}

    def _log(self, message):
        if self.log_callback:
            self.log_callback(message)
        else:
            print(message)

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._run_agent, daemon=True)
        self.thread.start()

    def _run_agent(self):
        asyncio.set_event_loop(asyncio.new_event_loop())
        self.loop = asyncio.get_event_loop()
        self.loop.run_until_complete(self._agent_main())

    async def _agent_main(self):
        self.client = AgentClient(str(self.config_path), data_dir=self.data_dir, log_callback=self._log)

        sys.path.insert(0, str(self.data_dir))
        import modules
        for finder, name, ispkg in pkgutil.iter_modules(modules.__path__):
            if name.startswith('_') or name == 'module_base':
                continue
            module = importlib.import_module('.' + name, package='modules')
            for attr in dir(module):
                cls = getattr(module, attr)
                if isinstance(cls, type) and issubclass(cls, Module) and cls != Module:
                    config_file = self.data_dir / "config" / f"{name}.json"
                    config = {}
                    if config_file.exists():
                        with open(config_file) as f:
                            config = json.load(f)
                    instance = cls(name, config)
                    instance.set_event_callback(
                        lambda etype, data: asyncio.create_task(
                            self.client.send_event(
                                etype,
                                data.get('level', 'info'),
                                data.get('module', name),
                                data.get('message', ''),
                                data.get('data', {})
                            )
                        )
                    )
                    self.client.modules[name] = instance
                    self.modules[name] = instance
                    self._log(f"Módulo cargado: {name}")

        await self.client.run()

    async def _start_module_async(self, module_name):
        """Corrutina para iniciar un módulo (se ejecuta en el loop del agente)."""
        if module_name in self.modules:
            await self.modules[module_name].async_start()
            self._log(f"Módulo {module_name} iniciado desde UI")
        else:
            self._log(f"Módulo {module_name} no encontrado")

    async def _stop_module_async(self, module_name):
        """Corrutina para detener un módulo."""
        if module_name in self.modules:
            await self.modules[module_name].stop()
            self._log(f"Módulo {module_name} detenido desde UI")
        else:
            self._log(f"Módulo {module_name} no encontrado")

    def start_module(self, module_name):
        if self.loop is None:
            self._log("Error: loop no inicializado")
            return
        asyncio.run_coroutine_threadsafe(self._start_module_async(module_name), self.loop)

    def stop_module(self, module_name):
        if self.loop is None:
            self._log("Error: loop no inicializado")
            return
        asyncio.run_coroutine_threadsafe(self._stop_module_async(module_name), self.loop)

    def get_modules_status(self):
        return {name: mod.is_running for name, mod in self.modules.items()}
    
    def get_module_logs(self, module_name, limit=50):
        if self.client:
            return self.client.get_module_logs(module_name, limit)
        return []

    def get_module_config(self, module_name):
        if module_name in self.modules:
            return self.modules[module_name].config
        return {}

    def configure_module(self, module_name, new_config):
        if module_name in self.modules:
            self.modules[module_name].config.update(new_config)
            # Guardar en archivo
            config_file = self.data_dir / "config" / f"{module_name}.json"
            with open(config_file, 'w') as f:
                json.dump(self.modules[module_name].config, f, indent=2)
            self._log(f"Configuración de {module_name} actualizada localmente")
            # Opcional: notificar al servidor si el módulo necesita reinicio, etc.