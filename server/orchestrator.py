import asyncio
import importlib
import pkgutil
import json
import logging
from typing import Dict, List
from modules.module_base import Module

logger = logging.getLogger("orchestrator")

class Orchestrator:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if hasattr(self, '_initialized') and self._initialized:
            return
        self._initialized = True
        self.modules: Dict[str, Module] = {}
        self._event_queues: List[asyncio.Queue] = []
        self._load_modules()

    def _load_modules(self):
        import modules
        for finder, name, ispkg in pkgutil.iter_modules(modules.__path__):
            if name.startswith('_') or name == 'module_base':
                continue
            module = importlib.import_module('.' + name, package='modules')
            for attr in dir(module):
                cls = getattr(module, attr)
                if isinstance(cls, type) and issubclass(cls, Module) and cls != Module:
                    config = self._load_config(name)
                    instance = cls(name, config)
                    self.modules[name] = instance
                    logger.info(f"Módulo continuo cargado: {name}")

    def _load_config(self, module_name: str) -> dict:
        try:
            with open(f'config/{module_name}.json') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning(f"Archivo de configuración no encontrado para {module_name}, usando vacío")
            return {}

    def save_config(self, module_name: str, config: dict):
        with open(f'config/{module_name}.json', 'w') as f:
            json.dump(config, f, indent=2)
        logger.info(f"Configuración guardada para {module_name}")

    async def _broadcast_event(self, event_type: str, data: dict):
        message = json.dumps({'type': event_type, 'data': data})
        for q in self._event_queues:
            await q.put(message)

    async def event_stream(self):
        queue = asyncio.Queue()
        self._event_queues.append(queue)
        try:
            while True:
                message = await queue.get()
                yield f"data: {message}\n\n"
        finally:
            self._event_queues.remove(queue)

    def start_module(self, name: str):
        if name in self.modules:
            self.modules[name].start()
            logger.info(f"Solicitado inicio de módulo: {name}")

    async def stop_module(self, name: str):
        if name in self.modules:
            await self.modules[name].stop()
            logger.info(f"Módulo detenido: {name}")

    def get_module_info(self, name: str) -> dict:
        mod = self.modules.get(name)
        if mod:
            return {
                'name': mod.name,
                'running': mod.is_running,
                'config': mod.config
            }
        return None

    def get_all_modules_info(self) -> dict:
        return {name: {'running': mod.is_running, 'config': mod.config}
                for name, mod in self.modules.items()}

    def configure_module(self, name: str, config: dict):
        if name in self.modules:
            self.modules[name].config.update(config)
            self.save_config(name, self.modules[name].config)
            logger.info(f"Módulo {name} reconfigurado")