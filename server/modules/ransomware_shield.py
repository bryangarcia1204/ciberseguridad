import asyncio
import os
import time
import fnmatch
from collections import deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from .process_monitor import get_process_list
from modules.module_base import Module
from modules import malware_scanner

class RansomwareShieldModule(Module):
    def __init__(self, name: str, config: dict = None):
        super().__init__(name, config)
        self.directories = self.config.get('directories', [])
        self.threshold = self.config.get('threshold', 50)
        self.window_seconds = self.config.get('window_seconds', 60)
        self.exclude_patterns = self.config.get('exclude_patterns', [])
        self.process_whitelist = self.config.get('process_whitelist', [])
        self.scan_with_antivirus = self.config.get('scan_with_antivirus', True)
        self.backend_antivirus = self.config.get('backend_antivirus', "auto")
        self.observer = None
        self.event_handler = None
        self.timestamps = deque()
        self.recent_files = deque(maxlen=50)
        self.queue = asyncio.Queue()

    async def run(self):
        self.loop = asyncio.get_event_loop()
        if not self.directories:
            await self.log('error', 'No se especificaron directorios a monitorear')
            return

        self.event_handler = RansomwareEventHandler(self)
        self.observer = Observer()
        for directory in self.directories:
            if os.path.exists(directory):
                self.observer.schedule(self.event_handler, directory, recursive=True)
                await self.log('info', f'Monitoreando directorio: {directory}')
            else:
                await self.log('warning', f'Directorio no existe: {directory}')

        self.observer.start()
        await self.log('info', f'Ransomware Shield iniciado (umbral: {self.threshold} cambios/{self.window_seconds}s)')

        try:
            while self.is_running:
                try:
                    src_path = await asyncio.wait_for(self.queue.get(), timeout=1.0)
                    self._add_event(src_path)
                except asyncio.TimeoutError:
                    pass
                self._check_threshold()
                await asyncio.sleep(0.1)
        except asyncio.CancelledError:
            self.observer.stop()
            self.observer.join()
            await self.log('info', 'Ransomware Shield detenido')
            raise

    def _add_event(self, src_path):
        if self._should_exclude(src_path):
            return
        self.timestamps.append(time.time())
        self.recent_files.append(src_path)
        asyncio.run_coroutine_threadsafe(
            self.store_data({'event': 'file_change', 'path': src_path}),
            self.loop
        )

    def _check_threshold(self):
        now = time.time()
        cutoff = now - self.window_seconds
        while self.timestamps and self.timestamps[0] < cutoff:
            self.timestamps.popleft()
        count = len(self.timestamps)
        if count >= self.threshold:
            sample_files = list(self.recent_files)
            suspicious_process = self._get_suspicious_process()
            if suspicious_process and suspicious_process in self.process_whitelist:
                return
            infected = []
            if self.scan_with_antivirus and sample_files:
                infected = self._scan_files(sample_files, self.backend_antivirus)
            alert_data = {
                'changes': count,
                'window': self.window_seconds,
                'sample_files': sample_files[:20],
                'infected_files': infected,
                'process': suspicious_process
            }
            if infected:
                asyncio.create_task(self.alert(
                    'ransomware_malicious',
                    f'¡Posible ransomware! {len(infected)} archivos sospechosos detectados en {self.window_seconds}s',
                    alert_data
                ))
            else:
                asyncio.create_task(self.alert(
                    'ransomware_surge',
                    f'Ráfaga de cambios detectada: {count} archivos en {self.window_seconds}s',
                    alert_data
                ))

    def _get_suspicious_process(self):
        """
        Obtiene el nombre del proceso con el PID más alto como heurística simple.
        (Podría mejorarse para usar CPU si se dispone de esa información.)
        """
        try:
            procs = get_process_list()
            if not procs:
                return None
            max_pid_proc = max(procs, key=lambda p: p['pid'])
            return max_pid_proc['name']
        except Exception as e:
            self.log('error', f'Error obteniendo proceso sospechoso: {e}')
            return None

    def _scan_files(self, files, backend):
        infected = []
        for file in files[:10]:
            try:
                if malware_scanner.scan_file(file, backend=backend):
                    infected.append(file)
            except Exception as e:
                self.log('error', f'Error escaneando {file}: {e}')
        return infected

    def _should_exclude(self, path):
        for pattern in self.exclude_patterns:
            if fnmatch.fnmatch(path, pattern):
                return True
        return False

    def queue_event(self, src_path):
        if self.loop is not None:
            asyncio.run_coroutine_threadsafe(self.queue.put(src_path), self.loop)

class RansomwareEventHandler(FileSystemEventHandler):
    def __init__(self, module):
        self.module = module

    def on_any_event(self, event):
        if event.is_directory:
            return
        self.module.queue_event(event.src_path)