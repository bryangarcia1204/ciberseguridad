import re
import asyncio
import platform
import subprocess
from collections import defaultdict, deque
from datetime import datetime, timedelta
from modules.module_base import Module
import ipaddress
import socket

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        if not re.match(r'^[\d\.]+$', ip):
            return False
        return True
    except ValueError:
        return False

def get_local_ips():
    local_ips = {"192.168.5.82", "127.0.0.1"}
    try:
        hostname = socket.gethostname()
        local_ips.add(socket.gethostbyname(hostname))
        for info in socket.getaddrinfo(hostname, None):
            ip = info[4][0]
            if not ip.startswith("127.") and ip != "::1":
                local_ips.add(ip)
    except:
        pass
    return local_ips

class LogMonitorModule(Module):
    async def run(self):
        self.logfile = self.config.get('logfile', '/var/log/apache2/access.log')
        
        # ===== NUEVOS PARÁMETROS =====
        self.threshold = self.config.get('threshold', 100)           # Número de peticiones
        self.time_window = self.config.get('time_window', 10)        # Ventana de tiempo en segundos
        self.ban_duration = self.config.get('ban_duration', 300)     # Duración del bloqueo en segundos (5 min)
        self.retry_interval = 30
        
        # ===== NUEVO: Estructura de datos con ventana de tiempo =====
        # ip -> deque de timestamps
        self.request_history = defaultdict(lambda: deque(maxlen=self.threshold * 2))
        # ip -> timestamp de desbloqueo
        self.banned_ips = {}
        
        start_time = asyncio.get_event_loop().time()
        self.local_ips = get_local_ips()
        
        await self.log('info', f'🔒 Protección DDoS: {self.threshold} peticiones en {self.time_window}s')
        await self.log('info', f'   IPs locales (no se bloquearán): {self.local_ips}')
        await self.log('info', f'   Duración del bloqueo: {self.ban_duration}s')

        try:
            import aiofiles
        except ImportError:
            await self.log('error', 'Para este módulo se necesita aiofiles: pip install aiofiles')
            return

        while self.is_running:
            try:
                async with aiofiles.open(self.logfile, 'r') as f:
                    await f.seek(0, 2)
                    await self.log('info', f'📊 Monitorizando archivo: {self.logfile}')
                    
                    while self.is_running:
                        line = await f.readline()
                        if line:
                            ip = self.extract_ip(line)
                            if ip:
                                # ===== NUEVO: Procesar con ventana de tiempo =====
                                await self._process_request(ip, line)
                        else:
                            # Limpiar historial antiguo cada 60 segundos
                            if asyncio.get_event_loop().time() - start_time > 60:
                                self._cleanup_old_history()
                                start_time = asyncio.get_event_loop().time()
                            await asyncio.sleep(0.1)
                            
            except FileNotFoundError:
                await self.log('warning', f'Archivo {self.logfile} no encontrado. Reintentando en {self.retry_interval} segundos...')
                await asyncio.sleep(self.retry_interval)
            except Exception as e:
                await self.log('error', f'Error inesperado: {e}')
                await asyncio.sleep(self.retry_interval)

    def extract_ip(self, line):
        # Intentar extraer IP al inicio de la línea (formato Apache común)
        match = re.search(r'^(\d+\.\d+\.\d+\.\d+)', line)
        if match:
            return match.group(1)
        
        # Intentar extraer IP de cualquier parte
        parts = line.split()
        ip_pattern = r'^\d+\.\d+\.\d+\.\d+$'
        for part in parts:
            if re.match(ip_pattern, part):
                return part
        return None
    
    def _cleanup_old_history(self):
        """Limpia historial de IPs que ya no son relevantes."""
        now = datetime.now()
        # Eliminar IPs con historial vacío o muy antiguo
        for ip in list(self.request_history.keys()):
            if len(self.request_history[ip]) == 0:
                del self.request_history[ip]

    async def _process_request(self, ip: str, line: str):
        """Procesa una petición con detección de DDoS por ventana de tiempo."""
        # 1. Verificar si la IP ya está bloqueada
        if ip in self.banned_ips:
            if datetime.now() < self.banned_ips[ip]:
                # IP sigue bloqueada, ignorar peticiones
                return
            else:
                # Bloqueo expirado
                del self.banned_ips[ip]
                await self.log('info', f'🔓 IP {ip} desbloqueada automáticamente (tiempo expirado)')
        
        # 2. Si es IP local, no procesar (no bloquear)
        if ip in self.local_ips:
            return
        
        now = datetime.now()
        
        # 3. Añadir timestamp al historial
        self.request_history[ip].append(now)
        
        # 4. Guardar línea para análisis (siempre)
        await self.store_data({'ip': ip, 'line': line})
        
        # 5. Verificar si la IP excede el umbral en la ventana de tiempo
        if self._is_ddos_attack(ip, now):
            # 6. Bloquear IP
            await self._block_ip(ip, f"{len(self.request_history[ip])} peticiones en {self.time_window}s")
            
            # 7. Limpiar historial para no volver a bloquear por el mismo ataque
            self.request_history[ip].clear()
    
    def _is_ddos_attack(self, ip: str, now: datetime) -> bool:
        """
        Verifica si una IP está haciendo un ataque DDoS.
        Usa sliding window: cuenta peticiones en los últimos N segundos.
        """
        if ip not in self.request_history:
            return False
        
        # Obtener timestamps de la IP
        timestamps = self.request_history[ip]
        
        # Si no hay suficientes peticiones, no hay ataque
        if len(timestamps) < self.threshold:
            return False
        
        # Ventana de tiempo: desde now - time_window hasta now
        window_start = now - timedelta(seconds=self.time_window)
        
        # Contar peticiones en la ventana de tiempo
        count_in_window = sum(1 for ts in timestamps if ts >= window_start)
        
        # Si el número de peticiones en la ventana supera el umbral → DDoS
        if count_in_window >= self.threshold:
            return True
        
        return False

    async def _block_ip(self, ip: str, reason: str):
        """Bloquea una IP (método interno)."""
        if not is_valid_ip(ip):
            await self.log('error', f'Intento de bloqueo de IP inválida: {ip}')
            return False
        
        # Verificar si ya está bloqueada
        if ip in self.banned_ips:
            return True
        
        # Registrar bloqueo en memoria
        self.banned_ips[ip] = datetime.now() + timedelta(seconds=self.ban_duration)
        
        # Bloquear en firewall
        success = await self.block_ip(ip)
        
        if success:
            # Alertar
            await self.alert('ddos_blocked', f'IP {ip} bloqueada por DDoS: {reason}', {
                'ip': ip,
                'reason': reason,
                'duration': self.ban_duration
            })
            await self.log('warning', f'🚫 IP {ip} bloqueada por DDoS: {reason}')
        else:
            await self.log('error', f'❌ No se pudo bloquear IP {ip}')
        
        return success

    async def block_ip(self, ip):
        """Bloquea una IP en el firewall del sistema (método original)."""
        if not is_valid_ip(ip):
            await self.log('error', f'Intento de bloqueo de IP inválida: {ip}')
            return False
        
        if ip in self.local_ips:
            await self.log('warning', f'No se bloquea IP local: {ip}')
            return False
        
        system = platform.system()
        try:
            if system == 'Windows':
                rule_name = f"LogMonitor_Block_{ip.replace('.', '_')}"
                
                # Eliminar regla si ya existe (para evitar duplicados)
                await asyncio.create_subprocess_exec(
                    'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                    f'name={rule_name}',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                # Crear regla de bloqueo
                proc = await asyncio.create_subprocess_exec(
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name={rule_name}', 'dir=in', 'action=block',
                    f'remoteip={ip}',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await proc.communicate()
                
                if proc.returncode != 0:
                    await self.log('error', f'Error al bloquear IP {ip}: {stderr.decode()}')
                    return False
                
                await self.log('info', f'IP {ip} bloqueada (regla {rule_name})')
                return True
            else:
                # Linux: usar iptables
                proc = await asyncio.create_subprocess_exec(
                    'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await proc.communicate()
                
                if proc.returncode != 0:
                    await self.log('error', f'Error al bloquear IP {ip}: {stderr.decode()}')
                    return False
                
                await self.log('info', f'IP {ip} bloqueada')
                return True
                
        except Exception as e:
            await self.log('error', f'No se pudo bloquear IP {ip}: {e}')
            return False
    
    # ===== NUEVO: Método para desbloquear IP manualmente =====
    async def unblock_ip(self, ip):
        """Desbloquea una IP del firewall."""
        if ip not in self.banned_ips:
            return False
        
        del self.banned_ips[ip]
        
        system = platform.system()
        try:
            if system == 'Windows':
                rule_name = f"LogMonitor_Block_{ip.replace('.', '_')}"
                proc = await asyncio.create_subprocess_exec(
                    'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                    f'name={rule_name}',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await proc.communicate()
            else:
                proc = await asyncio.create_subprocess_exec(
                    'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await proc.communicate()
            
            await self.log('info', f'🔓 IP {ip} desbloqueada manualmente')
            return True
        except Exception as e:
            await self.log('error', f'Error desbloqueando IP {ip}: {e}')
            return False