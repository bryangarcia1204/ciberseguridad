#!/usr/bin/env python3
"""
FIREWALL PYTHON - Alternativa al Firewall C++
=============================================
Firewall ligero implementado en Python para Windows/Linux.
No requiere compilación, funciona directamente.

Características:
- Filtrado de conexiones
- Bloqueo de IPs
- Reglas de firewall
- Rate limiting
- Detección de port scanning
- Logging de eventos

@author Cybersecurity System
@version 1.0.0
"""

import os
import re
import json
import time
import socket
import struct
import threading
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Set, Any
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict, deque
import logging
import platform

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('Firewall')


# ==================== ENUMS ====================

class ActionType(Enum):
    ALLOW = "allow"
    DENY = "deny"
    DROP = "drop"
    LOG = "log"
    RATE_LIMIT = "rate_limit"


class Protocol(Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ANY = "any"


class Severity(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


# ==================== DATA CLASSES ====================

@dataclass
class FirewallRule:
    id: int
    name: str
    action: ActionType
    protocol: Protocol
    source_ip: str = "any"
    source_port: int = 0  # 0 = any
    dest_ip: str = "any"
    dest_port: int = 0  # 0 = any
    enabled: bool = True
    priority: int = 5
    description: str = ""


@dataclass
class Connection:
    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    protocol: str
    state: str = "ESTABLISHED"
    bytes_sent: int = 0
    bytes_received: int = 0
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)


# ==================== FIREWALL CLASS ====================

class PythonFirewall:
    """Firewall implementado en Python."""
    
    def __init__(self):
        self.rules: List[FirewallRule] = []
        self.blocked_ips: Set[str] = set()
        self.whitelisted_ips: Set[str] = set()
        self.connections: Dict[str, Connection] = {}
        self.rate_limits: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        
        self._lock = threading.Lock()
        self._running = False
        self._stats = {
            'packets_processed': 0,
            'packets_allowed': 0,
            'packets_blocked': 0,
            'connections_tracked': 0
        }
        
        # Inicializar reglas por defecto
        self._init_default_rules()
    
    def _init_default_rules(self):
        """Inicializar reglas por defecto."""
        default_rules = [
            FirewallRule(1, "Allow DNS", ActionType.ALLOW, Protocol.UDP, dest_port=53, priority=10),
            FirewallRule(2, "Allow HTTP", ActionType.ALLOW, Protocol.TCP, dest_port=80, priority=9),
            FirewallRule(3, "Allow HTTPS", ActionType.ALLOW, Protocol.TCP, dest_port=443, priority=9),
            FirewallRule(4, "Allow SSH", ActionType.ALLOW, Protocol.TCP, dest_port=22, priority=8),
            FirewallRule(5, "Block Malicious Ports", ActionType.DENY, Protocol.TCP, dest_port=4444, priority=10),
            FirewallRule(6, "Default Deny", ActionType.DENY, Protocol.ANY, priority=1),
        ]
        self.rules = default_rules
    
    def start(self):
        """Iniciar el firewall."""
        self._running = True
        logger.info("Firewall Python iniciado")
        
        # Aplicar reglas al sistema operativo
        self._apply_system_rules()
        
        # Iniciar monitoreo de conexiones
        threading.Thread(target=self._monitor_connections, daemon=True).start()
    
    def stop(self):
        """Detener el firewall."""
        self._running = False
        logger.info("Firewall Python detenido")
        
        # Limpiar reglas del sistema
        self._clear_system_rules()
    
    def _apply_system_rules(self):
        """Aplicar reglas al firewall del sistema operativo."""
        system = platform.system()
        
        if system == "Windows":
            self._apply_windows_rules()
        elif system == "Linux":
            self._apply_linux_rules()
        else:
            logger.warning(f"Sistema {system} no soportado para reglas nativas")
    
    def _apply_windows_rules(self):
        """Aplicar reglas en Windows usando netsh."""
        try:
            # Bloquear IPs en la lista negra
            for ip in self.blocked_ips:
                cmd = f'netsh advfirewall firewall add rule name="CyberSec_Block_{ip}" dir=in action=block remoteip={ip}'
                subprocess.run(cmd, shell=True, capture_output=True)
                logger.info(f"IP bloqueada en Windows Firewall: {ip}")
            
            logger.info("Reglas aplicadas en Windows Firewall")
        except Exception as e:
            logger.error(f"Error aplicando reglas en Windows: {e}")
    
    def _apply_linux_rules(self):
        """Aplicar reglas en Linux usando iptables."""
        try:
            for ip in self.blocked_ips:
                cmd = f'iptables -A INPUT -s {ip} -j DROP'
                subprocess.run(cmd, shell=True, capture_output=True)
                logger.info(f"IP bloqueada en iptables: {ip}")
            
            logger.info("Reglas aplicadas en iptables")
        except Exception as e:
            logger.error(f"Error aplicando reglas en Linux: {e}")
    
    def _clear_system_rules(self):
        """Limpiar reglas del sistema."""
        system = platform.system()
        
        if system == "Windows":
            try:
                for ip in self.blocked_ips:
                    cmd = f'netsh advfirewall firewall delete rule name="CyberSec_Block_{ip}"'
                    subprocess.run(cmd, shell=True, capture_output=True)
            except Exception as e:
                logger.error(f"Error limpiando reglas: {e}")
    
    def _monitor_connections(self):
        """Monitorear conexiones activas."""
        while self._running:
            try:
                self._update_connections()
            except Exception as e:
                logger.error(f"Error monitoreando conexiones: {e}")
            
            time.sleep(5)
    
    def _update_connections(self):
        """Actualizar lista de conexiones."""
        system = platform.system()
        
        if system == "Windows":
            self._get_windows_connections()
        elif system == "Linux":
            self._get_linux_connections()
    
    def _get_windows_connections(self):
        """Obtener conexiones en Windows."""
        try:
            result = subprocess.run(
                ['netstat', '-ano'],
                capture_output=True,
                text=True
            )
            
            lines = result.stdout.strip().split('\n')[4:]  # Saltar headers
            
            with self._lock:
                self.connections.clear()
                
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 5:
                        protocol = parts[0]
                        local = parts[1]
                        remote = parts[2] if len(parts) > 2 else ''
                        state = parts[3] if len(parts) > 3 else ''
                        
                        try:
                            local_ip, local_port = local.rsplit(':', 1)
                            remote_ip, remote_port = remote.rsplit(':', 1) if ':' in remote else ('', '')
                            
                            conn_id = f"{remote_ip}:{remote_port}-{local_ip}:{local_port}"
                            self.connections[conn_id] = Connection(
                                source_ip=remote_ip,
                                source_port=int(remote_port) if remote_port.isdigit() else 0,
                                dest_ip=local_ip,
                                dest_port=int(local_port),
                                protocol=protocol,
                                state=state
                            )
                        except:
                            pass
                
                self._stats['connections_tracked'] = len(self.connections)
                
        except Exception as e:
            logger.error(f"Error obteniendo conexiones Windows: {e}")
    
    def _get_linux_connections(self):
        """Obtener conexiones en Linux."""
        try:
            with open('/proc/net/tcp', 'r') as f:
                lines = f.readlines()[1:]
                
                with self._lock:
                    for line in lines:
                        parts = line.strip().split()
                        if len(parts) >= 10:
                            local = parts[1]
                            remote = parts[2]
                            
                            local_ip, local_port = self._parse_hex_addr(local)
                            remote_ip, remote_port = self._parse_hex_addr(remote)
                            
                            conn_id = f"{remote_ip}:{remote_port}-{local_ip}:{local_port}"
                            self.connections[conn_id] = Connection(
                                source_ip=remote_ip,
                                source_port=remote_port,
                                dest_ip=local_ip,
                                dest_port=local_port,
                                protocol="TCP"
                            )
                    
                    self._stats['connections_tracked'] = len(self.connections)
                    
        except FileNotFoundError:
            pass
    
    def _parse_hex_addr(self, addr_str: str) -> Tuple[str, int]:
        """Parsear dirección hexadecimal de /proc/net."""
        try:
            addr, port = addr_str.split(':')
            addr_int = int(addr, 16)
            ip = '.'.join([str((addr_int >> (8 * i)) & 0xFF) for i in range(4)])
            port_int = int(port, 16)
            return ip, port_int
        except:
            return '0.0.0.0', 0
    
    # ==================== MÉTODOS PÚBLICOS ====================
    
    def block_ip(self, ip: str):
        """Bloquear una IP."""
        with self._lock:
            self.blocked_ips.add(ip)
            self.whitelisted_ips.discard(ip)
        
        # Aplicar al sistema
        if platform.system() == "Windows":
            cmd = f'netsh advfirewall firewall add rule name="CyberSec_Block_{ip}" dir=in action=block remoteip={ip}'
            subprocess.run(cmd, shell=True, capture_output=True)
        
        logger.info(f"IP bloqueada: {ip}")
    
    def unblock_ip(self, ip: str):
        """Desbloquear una IP."""
        with self._lock:
            self.blocked_ips.discard(ip)
        
        if platform.system() == "Windows":
            cmd = f'netsh advfirewall firewall delete rule name="CyberSec_Block_{ip}"'
            subprocess.run(cmd, shell=True, capture_output=True)
        
        logger.info(f"IP desbloqueada: {ip}")
    
    def whitelist_ip(self, ip: str):
        """Añadir IP a lista blanca."""
        with self._lock:
            self.whitelisted_ips.add(ip)
            self.blocked_ips.discard(ip)
        logger.info(f"IP añadida a whitelist: {ip}")
    
    def add_rule(self, rule: FirewallRule):
        """Añadir regla de firewall."""
        with self._lock:
            self.rules.append(rule)
            self.rules.sort(key=lambda r: r.priority, reverse=True)
        logger.info(f"Regla añadida: {rule.name}")
    
    def remove_rule(self, rule_id: int):
        """Eliminar regla."""
        with self._lock:
            self.rules = [r for r in self.rules if r.id != rule_id]
        logger.info(f"Regla eliminada: {rule_id}")
    
    def check_packet(self, source_ip: str, dest_ip: str, dest_port: int, protocol: Protocol) -> Tuple[bool, str]:
        """
        Verificar si un paquete debe ser permitido.
        Retorna (permitido, razón).
        """
        self._stats['packets_processed'] += 1
        
        # Verificar whitelist
        if source_ip in self.whitelisted_ips:
            self._stats['packets_allowed'] += 1
            return True, "IP en whitelist"
        
        # Verificar bloqueo
        if source_ip in self.blocked_ips:
            self._stats['packets_blocked'] += 1
            return False, "IP bloqueada"
        
        # Verificar reglas
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            # Verificar protocolo
            if rule.protocol != Protocol.ANY and rule.protocol != protocol:
                continue
            
            # Verificar puerto destino
            if rule.dest_port != 0 and rule.dest_port != dest_port:
                continue
            
            # Verificar IP destino
            if rule.dest_ip != "any" and rule.dest_ip != dest_ip:
                continue
            
            # Verificar IP origen
            if rule.source_ip != "any" and rule.source_ip != source_ip:
                continue
            
            # Regla coincide
            if rule.action == ActionType.ALLOW:
                self._stats['packets_allowed'] += 1
                return True, f"Regla: {rule.name}"
            elif rule.action == ActionType.DENY:
                self._stats['packets_blocked'] += 1
                return False, f"Regla: {rule.name}"
        
        # Default: denegar
        self._stats['packets_blocked'] += 1
        return False, "Default deny"
    
    def get_connections(self) -> List[Connection]:
        """Obtener conexiones activas."""
        with self._lock:
            return list(self.connections.values())
    
    def get_blocked_ips(self) -> List[str]:
        """Obtener IPs bloqueadas."""
        with self._lock:
            return list(self.blocked_ips)
    
    def get_rules(self) -> List[FirewallRule]:
        """Obtener reglas."""
        return self.rules.copy()
    
    def get_stats(self) -> Dict[str, int]:
        """Obtener estadísticas."""
        return self._stats.copy()
    
    def detect_port_scan(self, source_ip: str, time_window: int = 60, threshold: int = 10) -> bool:
        """Detectar si una IP está haciendo port scanning."""
        now = time.time()
        
        with self._lock:
            # Limpiar entradas antiguas
            self.rate_limits[source_ip] = deque(
                [t for t in self.rate_limits[source_ip] if now - t < time_window],
                maxlen=100
            )
            
            # Añadir timestamp actual
            self.rate_limits[source_ip].append(now)
            
            # Verificar umbral
            if len(self.rate_limits[source_ip]) >= threshold:
                return True
        
        return False


# ==================== MAIN ====================

def main():
    print("=" * 50)
    print("  FIREWALL PYTHON v1.0")
    print("  Sistema de Ciberseguridad")
    print("=" * 50)
    print()
    
    firewall = PythonFirewall()
    
    # Iniciar firewall
    firewall.start()
    
    print("\nFirewall iniciado.")
    print("Comandos disponibles:")
    print("  block <ip>    - Bloquear IP")
    print("  unblock <ip>  - Desbloquear IP")
    print("  list          - Ver IPs bloqueadas")
    print("  connections   - Ver conexiones activas")
    print("  stats         - Ver estadísticas")
    print("  rules         - Ver reglas")
    print("  exit          - Salir")
    print()
    
    try:
        while True:
            cmd = input("firewall> ").strip().lower()
            
            if cmd == "exit" or cmd == "quit":
                break
            
            elif cmd.startswith("block "):
                ip = cmd.split()[1]
                firewall.block_ip(ip)
            
            elif cmd.startswith("unblock "):
                ip = cmd.split()[1]
                firewall.unblock_ip(ip)
            
            elif cmd == "list":
                blocked = firewall.get_blocked_ips()
                if blocked:
                    print("IPs bloqueadas:")
                    for ip in blocked:
                        print(f"  - {ip}")
                else:
                    print("No hay IPs bloqueadas")
            
            elif cmd == "connections":
                conns = firewall.get_connections()
                print(f"Conexiones activas: {len(conns)}")
                for conn in conns[:10]:
                    print(f"  {conn.source_ip}:{conn.source_port} -> {conn.dest_ip}:{conn.dest_port} ({conn.protocol})")
            
            elif cmd == "stats":
                stats = firewall.get_stats()
                print("Estadísticas:")
                for key, value in stats.items():
                    print(f"  {key}: {value}")
            
            elif cmd == "rules":
                rules = firewall.get_rules()
                print("Reglas de firewall:")
                for rule in rules:
                    status = "✓" if rule.enabled else "✗"
                    print(f"  [{status}] {rule.id}: {rule.name} - {rule.action.value} ({rule.protocol.value})")
            
            else:
                print("Comando no reconocido. Escribe 'help' para ayuda.")
    
    except KeyboardInterrupt:
        print("\n")
    
    firewall.stop()
    print("Firewall detenido.")


if __name__ == "__main__":
    main()
