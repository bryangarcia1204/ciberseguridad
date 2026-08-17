# dhcp_server.py
"""
Servidor DHCP para redes empresariales pequeñas.
"""

import socket
import struct
import threading
import time
import logging
import json
import random
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple, List
from dataclasses import dataclass, field
import platform
import subprocess
from .logger import LOG_DIR

logger = logging.getLogger("DHCP-Server")

DHCP_PORT = 67
DHCP_CLIENT_PORT = 68
DHCP_MAGIC_COOKIE = b'\x63\x82\x53\x63'

DHCPDISCOVER = 1
DHCPOFFER = 2
DHCPREQUEST = 3
DHCPDECLINE = 4
DHCPACK = 5
DHCPNAK = 6
DHCPRELEASE = 7
DHCPINFORM = 8

OPTION_SUBNET_MASK = 1
OPTION_ROUTER = 3
OPTION_DNS_SERVER = 6
OPTION_HOST_NAME = 12
OPTION_DOMAIN_NAME = 15
OPTION_LEASE_TIME = 51
OPTION_MESSAGE_TYPE = 53
OPTION_SERVER_IDENTIFIER = 54
OPTION_REQUESTED_IP = 50
OPTION_END = 255


@dataclass
class DHCPLease:
    ip: str
    mac: str
    hostname: str = ""
    start_time: datetime = field(default_factory=datetime.now)
    end_time: datetime = field(default_factory=lambda: datetime.now() + timedelta(hours=24))
    is_active: bool = True
    last_renew: datetime = field(default_factory=datetime.now)

    def is_expired(self) -> bool:
        return datetime.now() > self.end_time

    def renew(self, hours: int = 24):
        self.end_time = datetime.now() + timedelta(hours=hours)
        self.last_renew = datetime.now()


class DHCPServer:
    """Servidor DHCP completo."""
    
    def __init__(self, config: dict = None):
        self.config = config or {}
        # Configuración con defaults
        self.subnet = self.config.get('subnet', '192.168.1.0/24')
        self.gateway = self.config.get('gateway', "0.0.0.0")  # El servidor es el gateway
        self.dns_servers = self.config.get('dns_servers', ["0.0.0.0", '8.8.8.8'])
        self.domain = self.config.get('domain', 'ciberseguridad.local')
        self.lease_time = self.config.get('lease_time', 86400)
        self.start_ip = self.config.get('start_ip', '192.168.1.50')
        self.end_ip = self.config.get('end_ip', '192.168.1.200')
        
        self.leases: Dict[str, DHCPLease] = {}
        self.ip_leases: Dict[str, str] = {}
        self.pending_offers: Dict[str, Tuple[str, datetime]] = {}
        self.running = False
        self.sock: Optional[socket.socket] = None
        self._lock = threading.Lock()
        
        self.network = ipaddress.IPv4Network(self.subnet, strict=False)
        self.ip_pool = self._generate_ip_pool()
        
        self._load_leases()
    
    def _generate_ip_pool(self) -> List[str]:
        start = int(ipaddress.IPv4Address(self.start_ip))
        end = int(ipaddress.IPv4Address(self.end_ip))
        return [str(ipaddress.IPv4Address(ip)) for ip in range(start, end + 1)]
    
    def _load_leases(self):
        try:
            with open("data/dhcp_leases.json", "r") as f:
                data = json.load(f)
                for mac, lease_data in data.items():
                    lease = DHCPLease(
                        ip=lease_data["ip"],
                        mac=mac,
                        hostname=lease_data.get("hostname", ""),
                        start_time=datetime.fromisoformat(lease_data["start_time"]),
                        end_time=datetime.fromisoformat(lease_data["end_time"]),
                        is_active=lease_data.get("is_active", True)
                    )
                    self.leases[mac] = lease
                    if lease.is_active and not lease.is_expired():
                        self.ip_leases[lease.ip] = mac
        except FileNotFoundError:
            pass
    
    def _save_leases(self):
        try:
            data = {}
            for mac, lease in self.leases.items():
                data[mac] = {
                    "ip": lease.ip,
                    "hostname": lease.hostname,
                    "start_time": lease.start_time.isoformat(),
                    "end_time": lease.end_time.isoformat(),
                    "is_active": lease.is_active
                }
            with open("data/dhcp_leases.json", "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Error guardando leases: {e}")
    
    def _get_available_ip(self, requested_ip: Optional[str] = None) -> Optional[str]:
        with self._lock:
            if requested_ip:
                if requested_ip in self.ip_pool and requested_ip not in self.ip_leases:
                    return requested_ip
            
            available = [ip for ip in self.ip_pool if ip not in self.ip_leases]
            if available:
                return random.choice(available)
            return None
    
    def _build_dhcp_response(self, xid: int, mac: str, yiaddr: str, siaddr: str,
                             message_type: int, options: Dict = None) -> bytes:
        op = b'\x02'
        htype = b'\x01'
        hlen = b'\x06'
        hops = b'\x00'
        xid_bytes = struct.pack('!I', xid)
        secs = b'\x00\x00'
        flags = b'\x00\x00'
        
        ciaddr = b'\x00\x00\x00\x00'
        yiaddr_bytes = socket.inet_aton(yiaddr) if yiaddr else b'\x00\x00\x00\x00'
        siaddr_bytes = socket.inet_aton(siaddr) if siaddr else b'\x00\x00\x00\x00'
        giaddr = b'\x00\x00\x00\x00'
        
        chaddr = bytes.fromhex(mac.replace(':', '')) + b'\x00' * 10
        sname = b'\x00' * 64
        file = b'\x00' * 128
        
        options_data = DHCP_MAGIC_COOKIE
        options_data += bytes([OPTION_MESSAGE_TYPE, 1, message_type])
        
        netmask = self.network.netmask.packed
        options_data += bytes([OPTION_SUBNET_MASK, 4]) + netmask
        
        gateway = socket.inet_aton(self.gateway)
        options_data += bytes([OPTION_ROUTER, 4]) + gateway
        
        dns_ips = [socket.inet_aton(dns) for dns in self.dns_servers]
        options_data += bytes([OPTION_DNS_SERVER, len(dns_ips) * 4]) + b''.join(dns_ips)
        
        domain_bytes = self.domain.encode()
        options_data += bytes([OPTION_DOMAIN_NAME, len(domain_bytes)]) + domain_bytes
        
        lease_bytes = struct.pack('!I', self.lease_time)
        options_data += bytes([OPTION_LEASE_TIME, 4]) + lease_bytes
        
        server_ip = socket.inet_aton(siaddr)
        options_data += bytes([OPTION_SERVER_IDENTIFIER, 4]) + server_ip
        
        if options and 'hostname' in options:
            hostname_bytes = options['hostname'].encode()
            options_data += bytes([OPTION_HOST_NAME, len(hostname_bytes)]) + hostname_bytes
        
        options_data += bytes([OPTION_END])
        
        packet = (op + htype + hlen + hops + xid_bytes + secs + flags +
                  ciaddr + yiaddr_bytes + siaddr_bytes + giaddr +
                  chaddr + sname + file + options_data)
        
        return packet
    
    def _handle_dhcp_discover(self, data: bytes, addr: tuple):
        try:
            xid = struct.unpack('!I', data[4:8])[0]
            mac = ':'.join(f'{b:02x}' for b in data[28:34])
            
            logger.debug(f"DHCPDISCOVER de {mac}")
            
            ip = self._get_available_ip()
            if not ip:
                logger.warning(f"No hay IPs disponibles para {mac}")
                return
            
            self.pending_offers[mac] = (ip, datetime.now())
            
            response = self._build_dhcp_response(
                xid=xid, mac=mac, yiaddr=ip, siaddr=addr[0],
                message_type=DHCPOFFER
            )
            
            self.sock.sendto(response, ('255.255.255.255', DHCP_CLIENT_PORT))
            
        except Exception as e:
            logger.error(f"Error en DHCPDISCOVER: {e}")
    
    def _handle_dhcp_request(self, data: bytes, addr: tuple):
        try:
            xid = struct.unpack('!I', data[4:8])[0]
            mac = ':'.join(f'{b:02x}' for b in data[28:34])
            
            requested_ip = None
            pos = data.find(DHCP_MAGIC_COOKIE) + 4
            while pos < len(data):
                opt = data[pos]
                if opt == OPTION_END:
                    break
                if opt == OPTION_REQUESTED_IP:
                    requested_ip = socket.inet_ntoa(data[pos+2:pos+6])
                    break
                length = data[pos+1]
                pos += length + 2
            
            ip = requested_ip or self._get_available_ip()
            if not ip:
                logger.warning(f"No hay IP disponible para {mac}")
                response = self._build_dhcp_response(
                    xid=xid, mac=mac, yiaddr='0.0.0.0',
                    siaddr=addr[0], message_type=DHCPNAK
                )
                self.sock.sendto(response, ('255.255.255.255', DHCP_CLIENT_PORT))
                return
            
            with self._lock:
                if mac in self.leases:
                    old_ip = self.leases[mac].ip
                    if old_ip in self.ip_leases:
                        del self.ip_leases[old_ip]
                
                lease = DHCPLease(
                    ip=ip, mac=mac,
                    hostname=self._extract_hostname(data),
                    end_time=datetime.now() + timedelta(seconds=self.lease_time)
                )
                self.leases[mac] = lease
                self.ip_leases[ip] = mac
                self.pending_offers.pop(mac, None)
                self._save_leases()
            
            response = self._build_dhcp_response(
                xid=xid, mac=mac, yiaddr=ip, siaddr=addr[0],
                message_type=DHCPACK,
                options={'hostname': lease.hostname} if lease.hostname else {}
            )
            
            self.sock.sendto(response, ('255.255.255.255', DHCP_CLIENT_PORT))
            logger.info(f"📡 DHCP: {ip} asignada a {mac} ({lease.hostname or 'desconocido'})")
            
            self._log_device_connection(mac, ip, lease.hostname)
            
        except Exception as e:
            logger.error(f"Error en DHCPREQUEST: {e}")
    
    def _extract_hostname(self, data: bytes) -> str:
        pos = data.find(DHCP_MAGIC_COOKIE) + 4
        while pos < len(data):
            opt = data[pos]
            if opt == OPTION_END:
                break
            if opt == OPTION_HOST_NAME:
                length = data[pos+1]
                return data[pos+2:pos+2+length].decode('utf-8', errors='ignore')
            length = data[pos+1]
            pos += length + 2
        return ""
    
    def _log_device_connection(self, mac: str, ip: str, hostname: str):
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'mac': mac,
            'ip': ip,
            'hostname': hostname,
            'event': 'dhcp_lease'
        }
        with open(f'{LOG_DIR}/dhcp_devices.log', 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    
    def _handle_dhcp_release(self, data: bytes, addr: tuple):
        try:
            mac = ':'.join(f'{b:02x}' for b in data[28:34])
            with self._lock:
                if mac in self.leases:
                    ip = self.leases[mac].ip
                    self.leases[mac].is_active = False
                    if ip in self.ip_leases:
                        del self.ip_leases[ip]
                    self._save_leases()
                    logger.info(f"DHCPRELEASE de {mac}: {ip} liberada")
        except Exception as e:
            logger.error(f"Error en DHCPRELEASE: {e}")
    
    def start(self):
        if self.running:
            return
        
        try:
            # Verificar si el puerto 67 está libre en Windows
            if platform.system() == "Windows":
                result = subprocess.run(["netstat", "-ano", "|", "findstr", ":67"], 
                                    shell=True, capture_output=True, text=True)
                if result.stdout.strip():
                    logger.warning("⚠️ Puerto 67 ocupado. Deteniendo servicio DHCP de Windows...")
                    subprocess.run(["net", "stop", "dhcpserver"], capture_output=True)
            
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.sock.bind(('0.0.0.0', DHCP_PORT))
            self.sock.settimeout(1.0)
            
            self.running = True
            
            cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
            cleanup_thread.start()
            
            main_thread = threading.Thread(target=self._run, daemon=True)
            main_thread.start()
            
            logger.info("=" * 60)
            logger.info(f"📡 SERVIDOR DHCP INICIADO")
            logger.info(f"   Red: {self.subnet}")
            logger.info(f"   Pool: {self.start_ip} - {self.end_ip}")
            logger.info(f"   Gateway: {self.gateway}")
            logger.info(f"   DNS: {', '.join(self.dns_servers)}")
            logger.info(f"   Dominio: {self.domain}")
            logger.info("=" * 60)
            
        except PermissionError:
            if platform.system() == "Windows":
                logger.error("❌ Permiso denegado para el puerto 67 en Windows.")
                logger.error("   Solución: Ejecutar como Administrador")
                logger.error("   O detener el servicio DHCP de Windows: net stop dhcpserver")
            else:
                logger.error(f"❌ Permiso denegado para el puerto {DHCP_PORT}. Ejecutar como root.")
        except Exception as e:
            logger.error(f"❌ Error iniciando DHCP: {e}")
    
    def _run(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(1024)
                
                if DHCP_MAGIC_COOKIE not in data:
                    continue
                
                pos = data.find(DHCP_MAGIC_COOKIE) + 4
                message_type = None
                while pos < len(data):
                    opt = data[pos]
                    if opt == OPTION_END:
                        break
                    if opt == OPTION_MESSAGE_TYPE:
                        message_type = data[pos+2]
                        break
                    length = data[pos+1]
                    pos += length + 2
                
                if message_type is None:
                    continue
                
                if message_type == DHCPDISCOVER:
                    self._handle_dhcp_discover(data, addr)
                elif message_type == DHCPREQUEST:
                    self._handle_dhcp_request(data, addr)
                elif message_type == DHCPRELEASE:
                    self._handle_dhcp_release(data, addr)
                
            except socket.timeout:
                continue
            except Exception as e:
                logger.error(f"Error en bucle DHCP: {e}")
    
    def _cleanup_loop(self):
        while self.running:
            time.sleep(60)
            with self._lock:
                expired = []
                for mac, lease in self.leases.items():
                    if lease.is_active and lease.is_expired():
                        expired.append(mac)
                        if lease.ip in self.ip_leases:
                            del self.ip_leases[lease.ip]
                        lease.is_active = False
                
                if expired:
                    self._save_leases()
                    logger.info(f"🧹 Limpiados {len(expired)} leases expirados")
    
    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()
        self._save_leases()
        logger.info("Servidor DHCP detenido")
    
    def get_active_leases(self) -> List[DHCPLease]:
        with self._lock:
            return [lease for lease in self.leases.values() if lease.is_active]
    
    def get_stats(self) -> Dict:
        with self._lock:
            total = len(self.leases)
            active = sum(1 for l in self.leases.values() if l.is_active)
            available = len([ip for ip in self.ip_pool if ip not in self.ip_leases])
        
        return {
            'total_leases': total,
            'active_leases': active,
            'available_ips': available,
            'total_pool': len(self.ip_pool)
        }


_dhcp_server: Optional[DHCPServer] = None

def start_dhcp_server(config: dict = None) -> DHCPServer:
    global _dhcp_server
    if _dhcp_server is None:
        _dhcp_server = DHCPServer(config)
        _dhcp_server.start()
    return _dhcp_server

def stop_dhcp_server():
    global _dhcp_server
    if _dhcp_server:
        _dhcp_server.stop()
        _dhcp_server = None

def get_dhcp_server() -> Optional[DHCPServer]:
    return _dhcp_server