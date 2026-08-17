import abc
import asyncio
from typing import Optional, Callable, Any
import logging
from datetime import datetime
from database import SessionLocal, ModuleData

class Module(abc.ABC):
    def __init__(self, name: str, config: dict = None):
        self.name = name
        self.config = config or {}
        self.is_running = False
        self._task: Optional[asyncio.Task] = None
        self.event_callback: Optional[Callable[[str, dict], Any]] = None
        self.logger = logging.getLogger(f"module.{name}")

    def set_event_callback(self, callback: Callable[[str, dict], Any]):
        self.event_callback = callback

    async def log(self, level: str, message: str):
        level_map = {
            'debug': logging.DEBUG,
            'info': logging.INFO,
            'warning': logging.WARNING,
            'error': logging.ERROR,
            'critical': logging.CRITICAL
        }
        log_level = level_map.get(level.lower(), logging.INFO)
        self.logger.log(log_level, message)
        if self.event_callback:
            await self.event_callback('log', {
                'module': self.name,
                'level': level,
                'message': message
            })

    async def alert(self, alert_type: str, description: str, data: dict = None):
        self.logger.warning(f"ALERT {alert_type}: {description} - {data}")
        if self.event_callback:
            await self.event_callback('alert', {
                'module': self.name,
                'type': alert_type,
                'description': description,
                'data': data or {}
            })

    async def store_data(self, data: dict, agent_id: int = 0):
        """Guarda datos estructurados para el análisis de IA."""
        try:
            db = SessionLocal()
            record = ModuleData(
                module=self.name,
                agent_id=agent_id,
                data=data,
                timestamp=datetime.utcnow()
            )
            db.add(record)
            db.commit()
            db.close()
        except Exception as e:
            self.logger.error(f"Error guardando datos del módulo: {e}")

    @abc.abstractmethod
    async def run(self):
        pass

    def start(self):
        if not self.is_running:
            self.is_running = True
            self._task = asyncio.create_task(self._run_wrapper())
            self.logger.info(f"Módulo {self.name} iniciado")

    async def _run_wrapper(self):
        try:
            await self.run()
        except asyncio.CancelledError:
            self.logger.info(f"Módulo {self.name} cancelado")
        except Exception as e:
            self.logger.exception(f"Error en módulo {self.name}: {e}")
        finally:
            self.is_running = False

    async def stop(self):
        if self.is_running and self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self.is_running = False
            self.logger.info(f"Módulo {self.name} detenido")