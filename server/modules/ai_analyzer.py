# modules/ai_analyzer.py
import asyncio
import logging
from typing import Dict, Type, Optional
from modules.module_base import Module
from .analyzers.base_analyzer import BaseAnalyzer
# Importar todos los analizadores específicos
from .analyzers.packet_sniffer_analyzer import PacketSnifferAnalyzer
from .analyzers.waf_analyzer import WafAnalyzer
from .analyzers.honeypot_analyzer import HoneypotAnalyzer
from .analyzers.log_monitor_analyzer import LogMonitorAnalyzer
from .analyzers.ransomware_analyzer import RansomwareAnalyzer
from .analyzers.network_scanner_analyzer import NetworkScannerAnalyzer   # nuevo
from .analyzers.integrity_checker_analyzer import IntegrityCheckerAnalyzer  # nuevo


logger = logging.getLogger(__name__)

class AIAnalyzerModule(Module):
    """
    Módulo orquestador que gestiona todos los analizadores específicos en hilos separados.
    """
    def __init__(self, name: str, config: dict = None):
        super().__init__(name, config)
        self.analyzers: Dict[str, BaseAnalyzer] = {}
        self._init_analyzers()
        self.loop: Optional[asyncio.AbstractEventLoop] = None

    def _init_analyzers(self):
        """Crea instancias de los analizadores según configuración."""
        analyzer_classes = {
            'packet_sniffer': PacketSnifferAnalyzer,
            'waf_module': WafAnalyzer,
            'honeypot': HoneypotAnalyzer,
            'log_monitor': LogMonitorAnalyzer,
            'ransomware_shield': RansomwareAnalyzer,
            'network_scanner': NetworkScannerAnalyzer,
            'integrity_checker': IntegrityCheckerAnalyzer,
        }
        for mod_name, analyzer_class in analyzer_classes.items():
            enabled = self.config.get(f'enable_{mod_name}', True)
            if not enabled:
                logger.info(f"Analizador {mod_name} deshabilitado por configuración")
                continue
            analyzer_config = self.config.get(f'{mod_name}_config', {})
            # Fusionar con configuración global si existe
            global_config = {k: v for k, v in self.config.items() if k not in analyzer_classes}
            full_config = {**global_config, **analyzer_config}
            try:
                analyzer = analyzer_class(mod_name, full_config)
                self.analyzers[mod_name] = analyzer
                logger.info(f"Analizador {mod_name} creado")
            except Exception as e:
                logger.error(f"Error creando analizador {mod_name}: {e}")

    async def run(self):
        """Método principal del módulo (corrutina)."""
        await self.log('info', 'Módulo AIAnalyzer iniciado')
        self.loop = asyncio.get_event_loop()

        # Inyectar el método de envío de alertas en cada analizador
        for analyzer in self.analyzers.values():
            analyzer._send_alert = self._send_alert_wrapper

        # Iniciar todos los analizadores (en sus hilos)
        for name, analyzer in self.analyzers.items():
            try:
                analyzer.set_loop_and_callback(self.loop, self._send_alert_wrapper)
                analyzer.start()
                await self.log('info', f"Analizador {name} iniciado")
            except Exception as e:
                await self.log('error', f"Error al iniciar analizador {name}: {e}")

        # Mantener el módulo vivo hasta que se detenga
        try:
            while self.is_running:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            await self.log('info', "AIAnalyzer cancelado, deteniendo analizadores...")
            await self.stop()
            raise

    async def _send_alert_wrapper(self, anomaly_data: Dict):
        """Envoltura para enviar alerta usando el loop del módulo."""
        await self.alert('ai_anomaly', f'Anomalía en {anomaly_data["module"]}', anomaly_data)

    async def stop(self):
        """Detiene todos los analizadores y el módulo."""
        for name, analyzer in self.analyzers.items():
            try:
                analyzer.stop()
                logger.info(f"Analizador {name} detenido")
            except Exception as e:
                logger.error(f"Error al detener analizador {name}: {e}")
        await super().stop()  # Llamar al stop de Module (que es async)