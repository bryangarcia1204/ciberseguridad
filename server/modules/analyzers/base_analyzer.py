# modules/base_analyzer.py
import abc
import threading
import time
import logging
import asyncio
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from database import SessionLocal, Event

logger = logging.getLogger(__name__)

class BaseAnalyzer(abc.ABC):
    """
    Clase base para todos los analizadores específicos de módulo.
    Cada analizador corre en su propio hilo y debe implementar:
    - _collect_data(): obtiene los datos históricos para entrenamiento.
    - _extract_features(): convierte los datos en características numéricas.
    - _train_model(): entrena el modelo de normalidad.
    - _detect_anomalies(): evalúa datos recientes y devuelve alertas.
    """
    
    def __init__(self, module_name: str, config: Dict[str, Any]):
        self.module_name = module_name
        self.config = config
        self.interval = config.get('analyzer_interval', 3600)      # Reentrenamiento (s)
        self.detection_interval = config.get('detection_interval', 50)  # Detección (s)
        self.window_days = config.get('window_days', 7)            # Ventana histórica (días)
        self.min_samples = config.get('min_samples', 100)          # Mínimo para entrenar
        self.model = None
        self.feature_names = None
        self.last_training = None
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self._loop = None  # Se asignará desde el orquestador
        self._send_alert_callback = None  # Función para enviar alertas
        self._stop_event = threading.Event()
        
    def start(self):
        """Inicia el analizador en un hilo separado."""
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self._run_loop, daemon=True)
            self.thread.start()
            logger.info(f"Analizador {self.module_name} iniciado")
    
    def stop(self):
        """Detiene el analizador."""
        self.running = False
        self._stop_event.set()
        if self.thread:
            self.thread.join(timeout=2)
            logger.info(f"Analizador {self.module_name} detenido")
    
    def _run_loop(self):
        """Bucle principal del hilo."""
        # Entrenamiento inicial
        self._train_if_needed(force=True)
        
        last_detection = time.time()
        while self.running:
            now = time.time()
            # Reentrenamiento periódico
            if now - (self.last_training or 0) > self.interval:
                self._train_if_needed()
            # Detección de anomalías
            if now - last_detection > self.detection_interval:
                anomalies = self._detect_anomalies()
                if anomalies:
                    self._report_anomalies(anomalies)
                last_detection = now
            self._stop_event.wait(5)  # espera hasta 5 segundos o hasta que se active
            if self._stop_event.is_set():
                break
            continue
    
    def _train_if_needed(self, force=False):
        """Entrena el modelo si no existe o ha pasado el intervalo."""
        if not self.model or force:
            data = self._collect_data()
            if len(data) >= self.min_samples:
                features = self._extract_features(data)
                if features is not None and not features.empty:
                    self.model, self.feature_names = self._train_model(features)
                    self.last_training = time.time()
                    logger.info(f"Modelo {self.module_name} entrenado con {len(features)} muestras")
                else:
                    logger.warning(f"{self.module_name}: características vacías después de extracción")
    
    def set_loop_and_callback(self, loop, callback):
        self._loop = loop
        self._send_alert_callback = callback

    @abc.abstractmethod
    def _collect_data(self) -> List[Event]:
        """Obtiene los eventos históricos del módulo desde la BD."""
        pass
    
    @abc.abstractmethod
    def _extract_features(self, events: List[Event]) -> Any:
        """Convierte los eventos en una matriz de características (ej. DataFrame)."""
        pass
    
    @abc.abstractmethod
    def _train_model(self, features):
        """Entrena el modelo y devuelve (modelo, lista_de_características)."""
        pass
    
    @abc.abstractmethod
    def _detect_anomalies(self) -> List[Dict[str, Any]]:
        """Analiza datos recientes y devuelve lista de alertas."""
        pass
    
    def _report_anomalies(self, anomalies: List[Dict[str, Any]]):
        for anom in anomalies:
            if self._loop and self._send_alert_callback:
                asyncio.run_coroutine_threadsafe(
                    self._send_alert_callback(anom),
                    self._loop
                )   
    
    async def _send_alert(self, anomaly_data: Dict):
        """Método auxiliar para enviar alerta (debe ser sobrescrito si se necesita)."""
        # Esta función será inyectada por el orquestador
        pass