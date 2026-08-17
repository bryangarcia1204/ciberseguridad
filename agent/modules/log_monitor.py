import re
import asyncio
import platform
import subprocess
from collections import defaultdict
from modules.module_base import Module
import ipaddress
import socket

import re

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        # Adicional: verificar que no tenga caracteres no deseados
        if not re.match(r'^[\d\.]+$', ip):
            return False
        return True
    except ValueError:
        return False

def get_local_ips():
    local_ips = {"192.168.5.82","127.0.0.1"}
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
        logfile = self.config.get('logfile', '/var/log/apache2/access.log')
        threshold = self.config.get('threshold', 100)
        requests = defaultdict(int)
        start_time = asyncio.get_event_loop().time()
        retry_interval = 30
        self.local_ips = get_local_ips()
        await self.log('info', f'IPs locales (no se bloquearán): {self.local_ips}')

        try:
            import aiofiles
        except ImportError:
            await self.log('error', 'Para este módulo se necesita aiofiles: pip install aiofiles')
            return

        while self.is_running:
            try:
                async with aiofiles.open(logfile, 'r') as f:
                    await f.seek(0, 2)
                    await self.log('info', f'Monitorizando archivo: {logfile}')
                    while self.is_running:
                        line = await f.readline()
                        if line:
                            ip = self.extract_ip(line)
                            if ip:
                                requests[ip] += 1
                                await self.store_data({'ip': ip, 'line': line})
                                if requests[ip] > threshold and not ip in self.local_ips:
                                    if await self.block_ip(ip):
                                        await self.alert('ip_blocked', f'IP {ip} bloqueada', {'ip': ip})
                                    requests[ip] = 0
                        else:
                            if asyncio.get_event_loop().time() - start_time > 60:
                                requests.clear()
                                start_time = asyncio.get_event_loop().time()
                            await asyncio.sleep(0.1)
            except FileNotFoundError:
                await self.log('warning', f'Archivo {logfile} no encontrado. Reintentando en {retry_interval} segundos...')
                await asyncio.sleep(retry_interval)
            except Exception as e:
                await self.log('error', f'Error inesperado: {e}')
                await asyncio.sleep(retry_interval)

    def extract_ip(self, line):
        match = re.search(r'^(\d+\.\d+\.\d+\.\d+)', line)
        if match:
            return match.group(1)
        parts = line.split()
        if len(parts) >= 5:
            ip_pattern = r'^\d+\.\d+\.\d+\.\d+$'
            for part in parts:
                if re.match(ip_pattern, part):
                    return part
        return None

    async def block_ip(self, ip):
        if not is_valid_ip(ip):
            await self.log('error', f'Intento de bloqueo de IP inválida: {ip}')
            return False
        if ip in self.local_ips:
            await self.log('warning', f'No se bloquea IP local: {ip}')
            return False
        system = platform.system()
        try:
            if system == 'Windows':
                rule_name = f"Block_IP_{ip.replace('.', '_')}"
                # Eliminar regla si ya existe (para evitar duplicados)
                await asyncio.create_subprocess_exec(
                    'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                    f'name={rule_name}',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
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