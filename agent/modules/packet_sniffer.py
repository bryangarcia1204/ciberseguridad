import asyncio
import platform
import socket
import struct
import json
from modules.module_base import Module

class PacketSnifferModule(Module):
    async def run(self):
        system = platform.system()
        method = self.config.get('method', 'auto')  # auto, raw, scapy
        verbose = self.config.get('verbose', False)
        loop = asyncio.get_event_loop()

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

    async def _process_scapy_packet(self, packet, verbose):
        try:
            if verbose:
                if packet.haslayer('IP'):
                    ip = packet['IP']
                    await self.log('debug', f'Scapy: IP {ip.src} -> {ip.dst} proto:{ip.proto}')
                    await self.store_data({
                        'src_ip': ip.src,
                        'dst_ip': ip.dst,
                        'protocol': ip.proto,
                        'size': len(packet)
                    })
                else:
                    await self.log('debug', f'Scapy: paquete capturado')
        except Exception as e:
            await self.log('error', f'Error procesando paquete scapy: {e}')

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

    async def parse_ip_packet(self, data, total_size, packet_count, verbose):
        try:
            version, hlen, ttl, proto, src, target, payload = self.ipv4_packet(data)
            if verbose:
                await self.log('debug', f'IP {src} -> {target} proto:{proto}')
            # Almacenar datos estructurados para IA
            await self.store_data({
                'src_ip': src,
                'dst_ip': target,
                'protocol': proto,
                'size': total_size
            })
        except Exception as e:
            if verbose:
                await self.log('error', f'Error parseando IP: {e}')

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