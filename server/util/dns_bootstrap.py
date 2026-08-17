# dns_bootstrap.py
"""
Servidor DNS Bootstrap para resolver el dominio del servidor.
"""

import socket
import threading
import logging
import subprocess
import platform
from typing import Optional

logger = logging.getLogger("DNS-Bootstrap")

DNS_PORT = 53
MAX_UDP_SIZE = 512
DNS_HEADER_SIZE = 12


class DNSBootstrapServer:
    """Servidor DNS minimalista para resolución local."""
    
    def __init__(self, config: dict = None):
        self.config = config or {}
        self.domain = self.config.get('domain', 'ciberseguridad.local')
        self.port = self.config.get('port', 53)
        self.waf_port = self.config.get('waf_port', 80)
        self.running = False
        self.sock: Optional[socket.socket] = None
        self.local_ip = self._get_local_ip()
        
    def _get_local_ip(self) -> str:
        """Obtiene la IP local de la máquina."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def _build_response(self, transaction_id: bytes, query_name: str) -> bytes:
        """Construye una respuesta DNS con la IP local."""
        flags = b'\x81\x80'
        qdcount = b'\x00\x01'
        ancount = b'\x00\x01'
        nscount = b'\x00\x00'
        arcount = b'\x00\x00'
        
        response = transaction_id + flags + qdcount + ancount + nscount + arcount
        
        # Question
        for part in query_name.split('.'):
            response += bytes([len(part)]) + part.encode()
        response += b'\x00'
        response += b'\x00\x01'  # Tipo A
        response += b'\x00\x01'  # Clase IN
        
        # Answer
        response += b'\xc0\x0c'
        response += b'\x00\x01'
        response += b'\x00\x01'
        response += b'\x00\x00\x01\x2c'  # TTL: 300 segundos
        response += b'\x00\x04'
        
        ip_bytes = socket.inet_aton(self.local_ip)
        response += ip_bytes
        
        return response
    
    def start(self):
        """Inicia el servidor DNS en un hilo separado."""
        if self.running:
            return
        
        self.running = True
        thread = threading.Thread(target=self._run, daemon=True)
        thread.start()
        logger.info(f"🌐 DNS Bootstrap: {self.domain} -> {self.local_ip}")

    def _run(self):
        """Bucle principal del servidor DNS con manejo para Windows."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(('0.0.0.0', self.port))
            self.sock.settimeout(1.0)
            
            while self.running:
                try:
                    data, addr = self.sock.recvfrom(MAX_UDP_SIZE)
                    self._handle_query(data, addr)
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"Error en DNS: {e}")
                    
        except PermissionError:
            if platform.system() == "Windows":
                logger.error("❌ Permiso denegado para el puerto 53 en Windows.")
                logger.error("   Solución: Ejecutar como Administrador")
                logger.error("   O detener el servicio DNS de Windows: net stop DNS")
            else:
                logger.error(f"❌ Permiso denegado para el puerto {self.port}. Ejecutar como root.")
        except OSError as e:
            if "Address already in use" in str(e):
                if platform.system() == "Windows":
                    logger.warning("⚠️ El puerto 53 ya está en uso. Deteniendo servicio DNS de Windows...")
                    try:
                        subprocess.run(["net", "stop", "DNS"], capture_output=True)
                        # Reintentar bind
                        self.sock.bind(('0.0.0.0', self.port))
                        logger.info("✅ Puerto 53 liberado, DNS iniciado")
                    except:
                        logger.error("No se pudo liberar el puerto 53. Usa 'net stop DNS' manualmente.")
                else:
                    logger.warning(f"⚠️ El puerto {self.port} ya está en uso.")
            else:
                logger.error(f"❌ Error iniciando DNS: {e}")
        finally:
            if self.sock:
                self.sock.close()
                self.sock = None
    
    def _handle_query(self, data: bytes, addr: tuple):
        """Procesa una consulta DNS."""
        try:
            transaction_id = data[0:2]
            
            pos = DNS_HEADER_SIZE
            name_parts = []
            while True:
                length = data[pos]
                if length == 0:
                    pos += 1
                    break
                name_parts.append(data[pos+1:pos+1+length].decode())
                pos += length + 1
            
            query_name = '.'.join(name_parts)
            query_type = int.from_bytes(data[pos:pos+2], 'big')
            
            if query_name == self.domain and query_type == 1:
                response = self._build_response(transaction_id, query_name)
                self.sock.sendto(response, addr)
                
        except Exception as e:
            logger.error(f"Error procesando consulta DNS: {e}")
    
    def stop(self):
        """Detiene el servidor DNS."""
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
        logger.info("DNS Bootstrap detenido")


_dns_server: Optional[DNSBootstrapServer] = None

def start_dns_bootstrap(config: dict = None) -> DNSBootstrapServer:
    """Inicia el servidor DNS Bootstrap (singleton)."""
    global _dns_server
    if _dns_server is None:
        _dns_server = DNSBootstrapServer(config)
        _dns_server.start()
    return _dns_server

def stop_dns_bootstrap():
    """Detiene el servidor DNS Bootstrap."""
    global _dns_server
    if _dns_server:
        _dns_server.stop()
        _dns_server = None