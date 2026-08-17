# modules/packet_sniffer.py (modificado)

import asyncio
import platform
import socket
import struct
import json
import ipaddress
from modules.module_base import Module

class PacketSnifferModule(Module):
    async def run(self):
        system = platform.system()
        method = self.config.get('method', 'auto')
        verbose = self.config.get('verbose', False)
        loop = asyncio.get_event_loop()
        
        # Obtener referencia al Traffic Controller
        self.traffic_controller = None
        if hasattr(self, '_orchestrator') and self._orchestrator:
            if 'traffic_controller' in self._orchestrator.modules:
                self.traffic_controller = self._orchestrator.modules['traffic_controller']
                await self.log('info', '🔗 Packet Sniffer conectado al Traffic Controller')
            else:
                await self.log('warning', '⚠️ Traffic Controller no disponible')

        # ===== NUEVO: Detectar IP del servidor =====
        self.server_ip = self._get_server_ip()
        await self.log('info', f'🖥️ IP del servidor detectada: {self.server_ip}')
        
        # ===== NUEVO: Configuración =====
        self.web_ports = self.config.get('web_ports', [80, 443, 8080, 8443, 8433])
        self.waf_port = self.config.get('waf_port', 80)
        self.admin_port = self.config.get('admin_port', 8433)
        self.waf_host = self.config.get('waf_host', self.server_ip)
        
        # ===== NUEVO: Crear socket raw para redirigir =====
        self.raw_socket = None
        if system == 'Windows':
            try:
                self.raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                self.raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                self.raw_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                await self.log('info', '✅ Socket raw creado para redirigir tráfico')
            except Exception as e:
                await self.log('warning', f'⚠️ No se pudo crear socket raw: {e}')
        elif system == 'Linux':
            try:
                self.raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
                await self.log('info', '✅ Socket raw creado en Linux')
            except Exception as e:
                await self.log('warning', f'⚠️ No se pudo crear socket raw: {e}')
        
        if system == 'Linux':
            await self._try_linux(loop, verbose)
            return

        if method == 'raw' or (method == 'auto' and system == 'Windows'):
            conn, promiscuous = await self._try_raw_windows(loop, verbose)
            if conn:
                await self._capture_loop_raw(conn, system, promiscuous, verbose, loop)
                return
            elif method == 'raw':
                await self.log('error', 'Método raw forzado falló, no se puede continuar')
                return
            else:
                await self.log('warning', 'Raw socket falló, intentando con scapy...')

        if method == 'scapy' or (method == 'auto' and system == 'Windows'):
            success = await self._try_scapy(loop, verbose)
            if success:
                return
            elif method == 'scapy':
                await self.log('error', 'Método scapy forzado falló, no se puede continuar')
                return
            else:
                await self.log('error', 'Ambos métodos fallaron, sniffer no disponible')

        await self.log('error', 'No se pudo iniciar el sniffer con ningún método disponible')
    
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
    
    # ===== NUEVO: Método para redirigir paquetes =====
    def _redirect_packet(self, packet_data: bytes, new_dest_ip: str, new_dest_port: int):
        """Reescribe el paquete para redirigirlo a un nuevo destino."""
        try:
            dest_ip_bytes = socket.inet_aton(new_dest_ip)
            packet_data = packet_data[:16] + dest_ip_bytes + packet_data[20:]
            
            protocol = packet_data[9]
            if protocol == 6:  # TCP
                tcp_start = 20
                packet_data = packet_data[:tcp_start + 2] + struct.pack('!H', new_dest_port) + packet_data[tcp_start + 4:]
            elif protocol == 17:  # UDP
                udp_start = 20
                packet_data = packet_data[:udp_start + 2] + struct.pack('!H', new_dest_port) + packet_data[udp_start + 4:]
            
            if self.raw_socket:
                self.raw_socket.sendto(packet_data, (new_dest_ip, 0))
                return True
        except Exception as e:
            self.logger.error(f"Error redirigiendo paquete: {e}")
            return False
    
    # ===== MODIFICADO: parse_ip_packet =====
    async def parse_ip_packet(self, data, total_size, packet_count, verbose):
        try:
            version, hlen, ttl, proto, src, target, payload = self.ipv4_packet(data)
            
            src_port = 0
            dst_port = 0
            if proto in [6, 17]:
                try:
                    if len(payload) >= 4:
                        src_port = struct.unpack('!H', payload[0:2])[0]
                        dst_port = struct.unpack('!H', payload[2:4])[0]
                except:
                    pass
            
            # ===== NUEVO: Solo procesar si el destino es el servidor =====
            is_targeting_server = (target == self.server_ip or target == '127.0.0.1' or target == '0.0.0.0')
            
            # ===== SOLO AQUÍ: Procesar tráfico web dirigido al servidor =====
            if self.traffic_controller:
                action, reason = self.traffic_controller.check_traffic(
                    source_ip=src,
                    dest_ip=target,
                    dest_port=dst_port,
                    protocol='tcp' if proto == 6 else 'udp'
                )
                
                if verbose:
                    await self.log('debug', f'🔍 Acción para {src} -> {target}:{dst_port} = {action.value}')

                if not is_targeting_server and action.value == 'ignore':
                    # El paquete no va al servidor → dejar pasar
                    if verbose:
                        await self.log('debug', f'⏭️ Paquete no dirigido al servidor: {src} -> {target}:{dst_port} (ignorado)')
                    await self.store_data({
                        'src_ip': src,
                        'dst_ip': target,
                        'protocol': proto,
                        'size': total_size,
                        'src_port': src_port,
                        'dest_port': dst_port,
                        'action': 'ignore',
                        'reason': reason
                    })
                    return
                
                # ===== NUEVO: Verificar si es puerto web =====
                if dst_port not in self.web_ports and action.value == 'ignore':
                    # No es puerto web → dejar pasar
                    if verbose:
                        await self.log('debug', f'⏭️ Puerto no web: {src} -> {target}:{dst_port} (ignorado)')
                    await self.store_data({
                        'src_ip': src,
                        'dst_ip': target,
                        'protocol': proto,
                        'size': total_size,
                        'src_port': src_port,
                        'dest_port': dst_port,
                        'action': 'ignore',
                        'reason': reason
                    })
                    return
                
                if action.value == 'redirect_waf':
                    await self.log('info', f'🔄 Redirigiendo {src} -> {target}:{dst_port} al WAF (puerto {self.waf_port})')
                    self._redirect_packet(data, self.waf_host, self.waf_port)
                    await self.store_data({
                        'event': 'redirect_to_waf',
                        'src_ip': src,
                        'dst_ip': target,
                        'src_port': src_port,
                        'dest_port': dst_port,
                        'redirect_to': f'{self.waf_host}:{self.waf_port}',
                        'reason': reason
                    })
                    return
                
                elif action.value == 'redirect_admin':
                    await self.log('info', f'✅ Redirigiendo {src} -> {target}:{dst_port} al Admin (puerto {self.admin_port})')
                    self._redirect_packet(data, self.waf_host, self.admin_port)
                    await self.store_data({
                        'event': 'redirect_to_admin',
                        'src_ip': src,
                        'dst_ip': target,
                        'src_port': src_port,
                        'dest_port': dst_port,
                        'redirect_to': f'{self.waf_host}:{self.admin_port}',
                        'reason': reason
                    })
                    return
                
                elif action.value == 'block':
                    await self.log('warning', f'🚫 Bloqueando paquete de {src} -> {target}:{dst_port} - {reason}')
                    await self.alert('packet_blocked', f'Paquete bloqueado desde {src}', {
                        'src_ip': src,
                        'dst_ip': target,
                        'src_port': src_port,
                        'dest_port': dst_port,
                        'reason': reason
                    })
                    return
                elif action.value == 'allow':
                    if verbose:
                        await self.log('debug', f'⏭️ Paquete no dirigido al servidor: {src} -> {target}:{dst_port} (ignorado)')
                    await self.store_data({
                        'src_ip': src,
                        'dst_ip': target,
                        'protocol': proto,
                        'size': total_size,
                        'src_port': src_port,
                        'dest_port': dst_port,
                        'action': 'allow',
                        'reason': reason
                    })
            
        except Exception as e:
            if verbose:
                await self.log('error', f'Error parseando IP: {e}')
    
    # ===== MODIFICADO: _process_scapy_packet =====
    async def _process_scapy_packet(self, packet, verbose):
        try:
            if packet.haslayer('IP'):
                ip = packet['IP']
                
                src_port = 0
                dst_port = 0
                if packet.haslayer('TCP'):
                    src_port = packet['TCP'].sport
                    dst_port = packet['TCP'].dport
                elif packet.haslayer('UDP'):
                    src_port = packet['UDP'].sport
                    dst_port = packet['UDP'].dport
                
                # ===== NUEVO: Solo procesar si el destino es el servidor =====
                is_targeting_server = (ip.dst == self.server_ip or ip.dst == '127.0.0.1' or ip.dst == '0.0.0.0')
                
                if not is_targeting_server:
                    if verbose:
                        await self.log('debug', f'⏭️ Scapy: paquete no dirigido al servidor: {ip.src} -> {ip.dst}')
                    return
                
                if dst_port not in self.web_ports:
                    if verbose:
                        await self.log('debug', f'⏭️ Scapy: puerto no web: {ip.src} -> {ip.dst}:{dst_port}')
                    return
                
                # Procesar tráfico web dirigido al servidor
                if self.traffic_controller:
                    action, reason = self.traffic_controller.check_traffic(
                        source_ip=ip.src,
                        dest_ip=ip.dst,
                        dest_port=dst_port,
                        protocol='tcp' if packet.haslayer('TCP') else 'udp'
                    )
                    
                    if action.value == 'redirect_waf':
                        await self.log('info', f'🔄 Scapy: Redirigiendo {ip.src} -> {ip.dst}:{dst_port} al WAF')
                        await self.store_data({
                            'event': 'scapy_redirect_waf',
                            'src_ip': ip.src,
                            'dst_ip': ip.dst,
                            'src_port': src_port,
                            'dest_port': dst_port,
                            'action': action.value
                        })
                        return
                    
                    elif action.value == 'redirect_admin':
                        await self.log('info', f'✅ Scapy: Redirigiendo {ip.src} -> {ip.dst}:{dst_port} al Admin')
                        await self.store_data({
                            'event': 'scapy_redirect_admin',
                            'src_ip': ip.src,
                            'dst_ip': ip.dst,
                            'src_port': src_port,
                            'dest_port': dst_port,
                            'action': action.value
                        })
                        return
                    
                    elif action.value == 'block':
                        await self.log('warning', f'🚫 Scapy: Bloqueando paquete de {ip.src} -> {ip.dst}:{dst_port}')
                        return
                
                if verbose:
                    await self.log('debug', f'Scapy: IP {ip.src} -> {ip.dst} proto:{ip.proto}')
            else:
                if verbose:
                    await self.log('debug', f'Scapy: paquete capturado')
        except Exception as e:
            await self.log('error', f'Error procesando paquete scapy: {e}')
    
    async def _try_raw_windows(self, loop, verbose):
        try:
            conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            conn.bind(('0.0.0.0', 0))
            conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            promiscuous = False
            try:
                conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                promiscuous = True
                await self.log('info', 'Modo promiscuo activado en Windows (método raw)')
            except Exception as e:
                await self.log('warning', f'No se pudo activar modo promiscuo (raw): {e}. Continuando sin él.')
            conn.setblocking(False)
            await self.log('info', 'Sniffer raw iniciado en Windows (captura solo IP)')
            return conn, promiscuous
        except PermissionError:
            await self.log('error', 'Se requieren permisos de administrador para sniffer raw en Windows')
            return None, False
        except Exception as e:
            await self.log('error', f'Error al iniciar sniffer raw en Windows: {e}')
            return None, False
        
    async def _analyze_with_traffic_controller(self, src_ip: str, dst_ip: str, protocol: int, port: int = 0):
        """Analiza el tráfico capturado con el Traffic Controller."""
        if not self.traffic_controller:
            return

        try:
            proto_name = 'tcp' if protocol == 6 else 'udp' if protocol == 17 else 'icmp' if protocol == 1 else 'unknown'
            
            # Si no es puerto web, no hacer nada
            web_ports = getattr(self.traffic_controller, 'web_ports', [80, 443, 8080, 8443, 8433])
            if port not in web_ports:
                return
            
            # Consultar al Traffic Controller
            action, reason = self.traffic_controller.check_traffic(
                source_ip=src_ip,
                dest_ip=dst_ip,
                dest_port=port,
                protocol=proto_name
            )

            # ===== NUEVO: Ejecutar acción =====
            if action.value == 'block':
                # ❌ Bloquear: descartar el paquete (no reenviar)
                await self.log('warning', f'🚫 Paquete bloqueado de {src_ip} -> {dst_ip}:{port} - {reason}')
                await self.alert('packet_blocked', f'Paquete bloqueado desde {src_ip}', {
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'port': port,
                    'protocol': proto_name,
                    'reason': reason
                })
                self._block_packet = True  # Flag para indicar bloqueo
                return
            
            elif action.value == 'redirect_waf':
                await self.log('debug', f'🔄 Tráfico web redirigido al WAF desde {src_ip} -> {dst_ip}:{port}')
                self._block_packet = False
            
            elif action.value == 'redirect_admin':
                await self.log('debug', f'✅ Tráfico web permitido al admin desde {src_ip} -> {dst_ip}:{port}')
                self._block_packet = False
            else:
                self._block_packet = False
                
        except Exception as e:
            await self.log('error', f'Error analizando tráfico: {e}')
            self._block_packet = False
        
    async def _try_scapy(self, loop, verbose):
        try:
            from scapy.all import conf, sniff
            conf.use_pcap = True
            await self.log('info', 'Intentando captura con Scapy...')
            queue = asyncio.Queue()
            def packet_handler(pkt):
                asyncio.run_coroutine_threadsafe(queue.put(pkt), loop)
            sniff_thread = asyncio.to_thread(sniff, prn=packet_handler, store=False)
            async def process_packets():
                while self.is_running:
                    try:
                        pkt = await asyncio.wait_for(queue.get(), timeout=1.0)
                        await self._process_scapy_packet(pkt, verbose)
                    except asyncio.TimeoutError:
                        continue
                    except Exception as e:
                        await self.log('error', f'Error procesando paquete: {e}')
            processor_task = asyncio.create_task(process_packets())
            await self.log('info', 'Sniffer con Scapy iniciado correctamente')
            while self.is_running:
                await asyncio.sleep(1)
            processor_task.cancel()
            return True
        except ImportError:
            await self.log('warning', 'Scapy no está instalado. Para usar método scapy, instala con: pip install scapy')
            return False
        except Exception as e:
            await self.log('error', f'Error al iniciar sniffer con scapy: {e}')
            return False

    async def _try_linux(self, loop, verbose):
        try:
            conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            conn.setblocking(False)
            await self.log('info', 'Sniffer iniciado en Linux (AF_PACKET, captura Ethernet)')
            await self._capture_loop_raw(conn, 'Linux', False, verbose, loop)
        except PermissionError:
            await self.log('error', 'Se requieren permisos de root para sniffer en Linux')
        except Exception as e:
            await self.log('error', f'Error al iniciar sniffer en Linux: {e}')

    async def _capture_loop_raw(self, conn, system, promiscuous, verbose, loop):
        packet_count = 0
        while self.is_running:
            try:
                raw_data, addr = await loop.sock_recvfrom(conn, 65536)
                packet_count += 1
                if system == 'Windows':
                    await self.parse_ip_packet(raw_data, len(raw_data), packet_count, verbose)
                else:
                    await self.parse_ethernet_frame(raw_data, len(raw_data), packet_count, verbose)
            except (socket.error, asyncio.TimeoutError):
                await asyncio.sleep(0.01)
            except Exception as e:
                await self.log('error', f'Error procesando paquete: {e}')

        if system == 'Windows' and conn and promiscuous:
            try:
                conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except:
                pass

    async def parse_ethernet_frame(self, data, total_size, packet_count, verbose):
        try:
            dest_mac, src_mac, eth_proto, payload = self.ethernet_frame(data)
            if verbose:
                await self.log('debug', f'Paquete #{packet_count}: {src_mac} -> {dest_mac} proto:{eth_proto}')
            if eth_proto == 8:  # IPv4
                await self.parse_ip_packet(payload, total_size, packet_count, verbose)
        except Exception as e:
            if verbose:
                await self.log('error', f'Error parseando Ethernet: {e}')

    def ethernet_frame(self, data):
        dest, src, proto = struct.unpack('!6s6sH', data[:14])
        return self.get_mac(dest), self.get_mac(src), socket.htons(proto), data[14:]

    def get_mac(self, b):
        return ':'.join(f'{x:02x}' for x in b).upper()

    def ipv4_packet(self, data):
        vhl = data[0]
        hlen = (vhl & 15) * 4
        ttl, proto, src, target = struct.unpack('!8xBB2x4s4s', data[:20])
        return vhl>>4, hlen, ttl, proto, self.ipv4(src), self.ipv4(target), data[hlen:]

    def ipv4(self, addr):
        return '.'.join(map(str, addr))