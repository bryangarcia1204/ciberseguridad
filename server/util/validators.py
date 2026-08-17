import ipaddress
import socket
from urllib.parse import urlparse

ALLOWED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
]

def validate_host(host: str) -> bool:
    """Valida que el host sea una IP privada o localhost."""
    try:
        ip = ipaddress.ip_address(host)
        for net in ALLOWED_NETWORKS:
            if ip in net:
                return True
        return False
    except ValueError:
        # No es IP, podría ser nombre de dominio local
        # Resolver y verificar IPs
        try:
            addrs = socket.getaddrinfo(host, None)
            for addr in addrs:
                ip = ipaddress.ip_address(addr[4][0])
                for net in ALLOWED_NETWORKS:
                    if ip in net:
                        return True
            return False
        except:
            return False

def validate_url(url: str) -> bool:
    """Valida que la URL apunte a un host permitido."""
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return False
    return validate_host(host)