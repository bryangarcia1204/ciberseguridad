# modules/traffic_controller.py
"""
Controlador de tráfico que decide el destino según el origen y puerto.
Solo procesa tráfico dirigido al servidor en puertos web.
"""

import asyncio
import socket
import ipaddress
import subprocess
import platform
from typing import Dict, List, Set, Tuple
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass
import os
import json

from modules.module_base import Module

class RuleAction(Enum):
    ALLOW = "allow"
    BLOCK = "block"
    DROP = "drop"

@dataclass
class FirewallRule:
    id: int
    name: str
    action: RuleAction
    source_ip: str = "any"
    dest_ip: str = "any"
    dest_port: int = 0
    protocol: str = "tcp"  # tcp, udp, icmp, any
    enabled: bool = True
    priority: int = 5
    description: str = ""

class TrafficAction(Enum):
    ALLOW = "allow"
    BLOCK = "block"
    REDIRECT_WAF = "redirect_waf"
    REDIRECT_ADMIN = "redirect_admin"
    IGNORE = "ignore"  # Tráfico que no debe ser procesado


class TrafficController(Module):
    """
    Controlador de tráfico que decide la acción a tomar.
    Solo procesa tráfico dirigido al servidor en puertos web.
    """
    
    def __init__(self, name: str, config: dict = None):
        super().__init__(name, config)
        
        # Detectar IP del servidor automáticamente
        self.server_ip = self._get_server_ip()
        self.hostname = socket.gethostname()
        
        # ===== Puertos web a proteger =====
        self.web_ports = self.config.get('web_ports', [80, 443, 8080, 8443, 8433])
        
        # Configuración desde JSON
        self.local_networks = self.config.get('local_networks', ['192.168.1.0/24'])
        self.admin_port = self.config.get('admin_port', 8433)
        self.waf_http_port = self.config.get('waf_http_port', 80)
        
        # Whitelist: incluye la IP del servidor automáticamente
        self.whitelist_ips = set(self.config.get('whitelist_ips', []))
        self.whitelist_ips.add(self.server_ip)
        self.whitelist_ips.add('127.0.0.1')
        
        # IPs bloqueadas
        self.blocked_ips: Set[str] = set()
        self.suspicious_ips: Set[str] = set()
        
        # Estadísticas
        self.stats = {
            'total_requests': 0,
            'admin_access': 0,
            'waf_redirects': 0,
            'blocked_attempts': 0,
            'ignored_traffic': 0,
            'non_web_traffic': 0,
            'external_traffic': 0
        }
        
        # Cache de decisiones
        self.decision_cache: Dict[str, Tuple[TrafficAction, datetime]] = {}
        self.cache_ttl = self.config.get('cache_ttl', 60)

        # ===== NUEVO: Almacén de reglas =====
        self.rules: List[FirewallRule] = []
        self.next_rule_id = 1
        self._load_rules()  # Cargar reglas persistentes
        
        self._initialized = False
    
    def _get_server_ip(self) -> str:
        """Obtiene la IP del servidor automáticamente."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
        
    def _load_rules(self):
        """Carga reglas desde archivo JSON."""
        rules_file = "config/firewall_rules.json"
        if os.path.exists(rules_file):
            try:
                with open(rules_file, 'r') as f:
                    data = json.load(f)
                    for rule_data in data:
                        rule = FirewallRule(
                            id=rule_data['id'],
                            name=rule_data['name'],
                            action=RuleAction(rule_data['action']),
                            source_ip=rule_data.get('source_ip', 'any'),
                            dest_ip=rule_data.get('dest_ip', 'any'),
                            dest_port=rule_data.get('dest_port', 0),
                            protocol=rule_data.get('protocol', 'tcp'),
                            enabled=rule_data.get('enabled', True),
                            priority=rule_data.get('priority', 5),
                            description=rule_data.get('description', '')
                        )
                        self.rules.append(rule)
                        self.next_rule_id = max(self.next_rule_id, rule.id + 1)
                self.logger.info(f"Cargadas {len(self.rules)} reglas desde archivo")
            except Exception as e:
                self.logger.error(f"Error cargando reglas: {e}")
    
    def _save_rules(self):
        """Guarda reglas en archivo JSON."""
        rules_file = "config/firewall_rules.json"
        try:
            os.makedirs(os.path.dirname(rules_file), exist_ok=True)
            data = [
                {
                    'id': r.id,
                    'name': r.name,
                    'action': r.action.value,
                    'source_ip': r.source_ip,
                    'dest_ip': r.dest_ip,
                    'dest_port': r.dest_port,
                    'protocol': r.protocol,
                    'enabled': r.enabled,
                    'priority': r.priority,
                    'description': r.description
                }
                for r in self.rules
            ]
            with open(rules_file, 'w') as f:
                json.dump(data, f, indent=2)
            self.logger.info(f"Guardadas {len(self.rules)} reglas")
        except Exception as e:
            self.logger.error(f"Error guardando reglas: {e}")
    
    async def run(self):
        """Bucle principal del controlador."""
        if not self._initialized:
            await self.log('info', f'🌐 Traffic Controller iniciado')
            await self.log('info', f'   Servidor IP: {self.server_ip}')
            await self.log('info', f'   Hostname: {self.hostname}')
            await self.log('info', f'   Whitelist: {list(self.whitelist_ips)}')
            await self.log('info', f'   Puertos web: {self.web_ports}')
            self._initialized = True
        
        while self.is_running:
            try:
                self._cleanup_cache()
                await self._send_stats()
                await asyncio.sleep(30)
            except Exception as e:
                await self.log('error', f'Error: {e}')
    
    def check_traffic(self, source_ip: str, dest_ip: str = None, 
                      dest_port: int = 0, protocol: str = "tcp",
                      domain: str = None) -> Tuple[TrafficAction, str]:
        """
        Verifica el tráfico y decide la acción a tomar.
        
        Retorna: (acción, razón)
        
        Lógica:
        1. Si el destino NO es el servidor → IGNORE
        2. Si el puerto NO es web → IGNORE
        3. Si está en whitelist → REDIRECT_ADMIN
        4. Si está en blacklist → BLOCK
        5. Si es IP local → REDIRECT_WAF
        6. Si es IP externa → REDIRECT_WAF
        7. Si es sospechosa → BLOCK
        """
        self.stats['total_requests'] += 1
        
        # ===== 1. Verificar si el destino es el servidor =====
        dest_ip = dest_ip or ''
        is_targeting_server = (
            dest_ip == self.server_ip or 
            dest_ip == '127.0.0.1' or 
            dest_ip == '0.0.0.0' or
            dest_ip == ''  # Si no hay destino, asumimos que es para el servidor
        )
        
        if not is_targeting_server:
            self.stats['ignored_traffic'] += 1
            return TrafficAction.IGNORE, f"Tráfico no dirigido al servidor: {dest_ip}"
        
        # ===== 2. Verificar si es puerto web =====
        if dest_port not in self.web_ports:
            self.stats['non_web_traffic'] += 1
            return TrafficAction.IGNORE, f"Puerto no web: {dest_port}"
        
        # ===== 3. Verificar caché =====
        cache_key = f"{source_ip}:{dest_ip}:{dest_port}"
        if cache_key in self.decision_cache:
            action, expires = self.decision_cache[cache_key]
            if datetime.now() < expires:
                return action, "Caché"
        
        # ===== 4. Verificar bloqueos =====
        if source_ip in self.blocked_ips:
            self.stats['blocked_attempts'] += 1
            action = TrafficAction.BLOCK
            self.decision_cache[cache_key] = (action, datetime.now() + timedelta(seconds=self.cache_ttl))
            return action, "IP bloqueada"
        
        # ===== 5. Verificar whitelist =====
        if source_ip in self.whitelist_ips:
            self.stats['admin_access'] += 1
            action = TrafficAction.REDIRECT_ADMIN
            self.decision_cache[cache_key] = (action, datetime.now() + timedelta(seconds=self.cache_ttl))
            return action, f"Admin access desde {source_ip}"
        
        # ===== 6. Verificar si es IP local =====
        if self._is_local_ip(source_ip):
            self.stats['waf_redirects'] += 1
            action = TrafficAction.REDIRECT_WAF
            self.decision_cache[cache_key] = (action, datetime.now() + timedelta(seconds=self.cache_ttl))
            return action, f"Local pero no whitelist: {source_ip} -> puerto {dest_port}"
        
        # ===== 7. IP externa =====
        if self._is_suspicious(source_ip):
            self.blocked_ips.add(source_ip)
            self.stats['blocked_attempts'] += 1
            action = TrafficAction.BLOCK
            self.decision_cache[cache_key] = (action, datetime.now() + timedelta(seconds=self.cache_ttl))
            return action, "IP sospechosa bloqueada"
        
        # ===== 8. Por defecto: Allow =====
        self.stats['external_traffic'] += 1
        action = TrafficAction.ALLOW
        self.decision_cache[cache_key] = (action, datetime.now() + timedelta(seconds=self.cache_ttl))
        return action, f"Externo: {source_ip} -> puerto {dest_port}"
    
    def _is_local_ip(self, ip: str) -> bool:
        """Verifica si una IP es local."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for network in self.local_networks:
                if ip_obj in ipaddress.ip_network(network, strict=False):
                    return True
            return False
        except:
            return False
    
    def _is_suspicious(self, ip: str) -> bool:
        """Verifica si una IP es sospechosa."""
        return ip in self.suspicious_ips
    
    def _cleanup_cache(self):
        """Limpia la caché de decisiones expiradas."""
        now = datetime.now()
        expired = [k for k, v in self.decision_cache.items() if v[1] < now]
        for k in expired:
            del self.decision_cache[k]
    
    async def _send_stats(self):
        """Envía estadísticas al servidor."""
        await self.store_data({
            'type': 'traffic_stats',
            'data': self.stats
        })
    
    # ==================== MÉTODOS PÚBLICOS ====================
    
    def add_whitelist(self, ip: str):
        """Añade una IP a la whitelist."""
        self.whitelist_ips.add(ip)
        asyncio.create_task(self.log('info', f'IP añadida a whitelist: {ip}'))
    
    def remove_whitelist(self, ip: str):
        """Elimina una IP de la whitelist."""
        if ip != self.server_ip and ip != '127.0.0.1':
            self.whitelist_ips.discard(ip)
            asyncio.create_task(self.log('info', f'IP eliminada de whitelist: {ip}'))
    
    def block_ip(self, ip: str, reason: str = ""):
        """Bloquea una IP en el firewall del sistema y en la lista interna."""
        if ip in self.blocked_ips:
            return
        
        # 1. Añadir a lista interna
        self.blocked_ips.add(ip)
        
        # 2. Bloquear en el firewall del sistema operativo
        self._apply_firewall_block(ip)
        
        # 3. Registrar y alertar
        asyncio.create_task(self.log('warning', f'🚫 IP bloqueada: {ip} - {reason}'))
        asyncio.create_task(self.alert('ip_blocked', f'IP bloqueada: {ip}', {'ip': ip, 'reason': reason}))
    
    def unblock_ip(self, ip: str):
        """Desbloquea una IP del firewall y de la lista interna."""
        if ip not in self.blocked_ips:
            return
        
        # 1. Eliminar de lista interna
        self.blocked_ips.discard(ip)
        
        # 2. Eliminar regla del firewall
        self._remove_firewall_block(ip)
        
        # 3. Registrar
        asyncio.create_task(self.log('info', f'✅ IP desbloqueada: {ip}'))
    
    def _apply_firewall_block(self, ip: str):
        """Aplica bloqueo en el firewall del sistema operativo."""
        system = platform.system()
        try:
            if system == 'Windows':
                # Crear regla de bloqueo en Windows Firewall (entrada y salida)
                cmd_in = f'netsh advfirewall firewall add rule name="CyberSec_Block_{ip}" dir=in action=block remoteip={ip}'
                cmd_out = f'netsh advfirewall firewall add rule name="CyberSec_Block_{ip}_out" dir=out action=block remoteip={ip}'
                subprocess.run(cmd_in, shell=True, capture_output=True)
                subprocess.run(cmd_out, shell=True, capture_output=True)
            elif system == 'Linux':
                # Bloquear en iptables (entrada y salida)
                cmd_in = f'iptables -A INPUT -s {ip} -j DROP'
                cmd_out = f'iptables -A OUTPUT -d {ip} -j DROP'
                subprocess.run(cmd_in, shell=True, capture_output=True)
                subprocess.run(cmd_out, shell=True, capture_output=True)
            else:
                self.logger.warning(f'Bloqueo no soportado en {system}')
        except Exception as e:
            self.logger.error(f'Error bloqueando IP {ip}: {e}')
    
    def _remove_firewall_block(self, ip: str):
        """Elimina regla de bloqueo del firewall."""
        system = platform.system()
        try:
            if system == 'Windows':
                cmd_in = f'netsh advfirewall firewall delete rule name="CyberSec_Block_{ip}"'
                cmd_out = f'netsh advfirewall firewall delete rule name="CyberSec_Block_{ip}_out"'
                subprocess.run(cmd_in, shell=True, capture_output=True)
                subprocess.run(cmd_out, shell=True, capture_output=True)
            elif system == 'Linux':
                # iptables -D elimina la primera regla que coincida
                # Nota: si hay múltiples reglas, esto elimina solo la primera
                cmd_in = f'iptables -D INPUT -s {ip} -j DROP'
                cmd_out = f'iptables -D OUTPUT -d {ip} -j DROP'
                subprocess.run(cmd_in, shell=True, capture_output=True)
                subprocess.run(cmd_out, shell=True, capture_output=True)
        except Exception as e:
            self.logger.error(f'Error desbloqueando IP {ip}: {e}')

    # ===== NUEVO: Gestión de reglas =====

    def add_rule(self, rule: FirewallRule) -> int:
        """Añade una nueva regla y la aplica en el firewall."""
        rule.id = self.next_rule_id
        self.next_rule_id += 1
        self.rules.append(rule)
        self._save_rules()
        
        # Aplicar la regla en el firewall
        self._apply_rule_to_firewall(rule)
        
        self.logger.info(f"Regla añadida: {rule.name} (ID: {rule.id})")
        return rule.id

    def remove_rule(self, rule_id: int) -> bool:
        """Elimina una regla y la quita del firewall."""
        for i, rule in enumerate(self.rules):
            if rule.id == rule_id:
                # Eliminar del firewall
                self._remove_rule_from_firewall(rule)
                # Eliminar de la lista
                removed = self.rules.pop(i)
                self._save_rules()
                self.logger.info(f"Regla eliminada: {removed.name} (ID: {rule_id})")
                return True
        return False

    def get_rules(self) -> List[Dict]:
        """Devuelve lista de reglas en formato serializable."""
        return [
            {
                'id': r.id,
                'name': r.name,
                'action': r.action.value,
                'source_ip': r.source_ip,
                'dest_ip': r.dest_ip,
                'dest_port': r.dest_port,
                'protocol': r.protocol,
                'enabled': r.enabled,
                'priority': r.priority,
                'description': r.description
            }
            for r in self.rules
        ]

    def enable_rule(self, rule_id: int) -> bool:
        """Habilita una regla y la aplica en el firewall."""
        for rule in self.rules:
            if rule.id == rule_id:
                rule.enabled = True
                self._apply_rule_to_firewall(rule)
                self._save_rules()
                self.logger.info(f"Regla habilitada: {rule.name} (ID: {rule_id})")
                return True
        return False

    def disable_rule(self, rule_id: int) -> bool:
        """Deshabilita una regla y la quita del firewall."""
        for rule in self.rules:
            if rule.id == rule_id:
                rule.enabled = False
                self._remove_rule_from_firewall(rule)
                self._save_rules()
                self.logger.info(f"Regla deshabilitada: {rule.name} (ID: {rule_id})")
                return True
        return False

    # ===== NUEVO: Aplicar reglas al firewall del SO =====

    def _apply_rule_to_firewall(self, rule: FirewallRule):
        """Aplica una regla al firewall del sistema operativo."""
        if not rule.enabled:
            return
        
        system = platform.system()
        try:
            if system == 'Windows':
                self._apply_windows_rule(rule)
            elif system == 'Linux':
                self._apply_linux_rule(rule)
            else:
                self.logger.warning(f'Reglas no soportadas en {system}')
        except Exception as e:
            self.logger.error(f"Error aplicando regla {rule.id}: {e}")

    def _apply_windows_rule(self, rule: FirewallRule):
        """Aplica regla en Windows Firewall usando netsh."""
        rule_name = f"CyberSec_Rule_{rule.id}_{rule.name.replace(' ', '_')}"
        
        # Construir comando netsh
        cmd = [
            'netsh', 'advfirewall', 'firewall', 'add', 'rule',
            f'name={rule_name}',
            f'description={rule.description or rule.name}',
            f'dir=in',
            f'action={rule.action.value}'
        ]
        
        if rule.source_ip != 'any':
            cmd.append(f'sourceip={rule.source_ip}')
        if rule.dest_ip != 'any':
            cmd.append(f'destip={rule.dest_ip}')
        if rule.dest_port != 0:
            cmd.append(f'protocol={rule.protocol}')
            cmd.append(f'localport={rule.dest_port}')
        else:
            cmd.append(f'protocol={rule.protocol}')
        
        # Ejecutar comando
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            self.logger.error(f"Error aplicando regla Windows: {result.stderr}")
        else:
            self.logger.debug(f"Regla aplicada en Windows: {rule_name}")

    def _apply_linux_rule(self, rule: FirewallRule):
        """Aplica regla en Linux usando iptables."""
        cmd = ['iptables']
        
        # Determinar tabla y cadena
        if rule.action == RuleAction.ALLOW:
            cmd.extend(['-A', 'INPUT', '-j', 'ACCEPT'])
        elif rule.action == RuleAction.BLOCK or rule.action == RuleAction.DROP:
            cmd.extend(['-A', 'INPUT', '-j', 'DROP'])
        
        if rule.source_ip != 'any':
            cmd.extend(['-s', rule.source_ip])
        if rule.dest_ip != 'any':
            cmd.extend(['-d', rule.dest_ip])
        if rule.dest_port != 0:
            cmd.extend(['--dport', str(rule.dest_port)])
        if rule.protocol != 'any':
            cmd.extend(['-p', rule.protocol])
        
        # Ejecutar
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            self.logger.error(f"Error aplicando regla Linux: {result.stderr}")
        else:
            self.logger.debug(f"Regla aplicada en Linux: {rule.name}")

    def _remove_rule_from_firewall(self, rule: FirewallRule):
        """Elimina una regla del firewall del sistema."""
        system = platform.system()
        try:
            if system == 'Windows':
                rule_name = f"CyberSec_Rule_{rule.id}_{rule.name.replace(' ', '_')}"
                subprocess.run(
                    ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_name}'],
                    capture_output=True
                )
            elif system == 'Linux':
                # iptables -D elimina la primera regla que coincida
                cmd = ['iptables', '-D', 'INPUT']
                if rule.source_ip != 'any':
                    cmd.extend(['-s', rule.source_ip])
                if rule.dest_ip != 'any':
                    cmd.extend(['-d', rule.dest_ip])
                if rule.dest_port != 0:
                    cmd.extend(['--dport', str(rule.dest_port)])
                if rule.protocol != 'any':
                    cmd.extend(['-p', rule.protocol])
                if rule.action == RuleAction.ALLOW:
                    cmd.append('-j')
                    cmd.append('ACCEPT')
                else:
                    cmd.append('-j')
                    cmd.append('DROP')
                subprocess.run(cmd, capture_output=True)
        except Exception as e:
            self.logger.error(f"Error eliminando regla {rule.id}: {e}")
    
    def get_stats(self) -> Dict:
        """Obtiene estadísticas."""
        return {
            **self.stats,
            'server_ip': self.server_ip,
            'whitelist_ips': len(self.whitelist_ips),
            'blocked_ips': len(self.blocked_ips),
            'suspicious_ips': len(self.suspicious_ips),
            'cache_size': len(self.decision_cache),
            'local_networks': self.local_networks,
            'web_ports': self.web_ports
        }
    
    def get_decision(self, source_ip: str, dest_ip: str = None, 
                     dest_port: int = 0) -> Tuple[TrafficAction, str]:
        """
        Método público para obtener una decisión sin modificar estadísticas.
        Útil para consultas externas.
        """
        # Verificar caché
        cache_key = f"{source_ip}:{dest_ip}:{dest_port}"
        if cache_key in self.decision_cache:
            action, expires = self.decision_cache[cache_key]
            if datetime.now() < expires:
                return action, "Caché"
        
        # Usar la lógica principal
        return self.check_traffic(source_ip, dest_ip, dest_port)