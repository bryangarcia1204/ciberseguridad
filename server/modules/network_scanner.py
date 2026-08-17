import json
import asyncio
import ipaddress
import ifaddr
from modules.module_base import Module

class NetworkScannerModule(Module):
    async def run(self):
        try:
            from scapy.all import ARP, Ether, srp, conf
        except ImportError:
            await self.log('error', 'Scapy no está instalado. Ejecute: pip install scapy')
            return
        except Exception as e:
            await self.log('error', f'Error al cargar Scapy: {e}. En Windows, asegúrese de tener Npcap instalado.')
            return

        # Configuración
        networks_config = self.config.get('networks', None)
        ip_range = self.config.get('ip_range', "")
        interface = self.config.get('interface', None)
        scan_all = self.config.get('scan_all_networks', ip_range is None and networks_config is None)
        known_file = self.config.get('known_devices_file', 'known_devices.json')
        interval = self.config.get('scan_interval', 60)
        timeout = self.config.get('timeout', 5)  # Timeout en segundos (aumentado a 5 por defecto)

        # Construir lista de (red, interfaz) a escanear
        scan_targets = []

        if networks_config:
            for net in networks_config:
                ip_range_net = net.get('ip_range')
                if not ip_range_net:
                    continue
                iface = net.get('interface', interface)
                scan_targets.append((ip_range_net, iface))
            await self.log('info', f'Escaneando {len(scan_targets)} redes configuradas manualmente')
        elif ip_range:
            scan_targets.append((ip_range, interface))
            await self.log('info', f'Escaneando red única: {ip_range}')
        elif scan_all:
            networks = self._get_all_networks()
            if not networks:
                await self.log('error', 'No se pudo detectar ninguna red. Escaneo detenido.')
                return
            # Convertir a lista de tuplas (red, interfaz=None)
            scan_targets = [(net, None) for net in networks]
            await self.log('info', f'Redes detectadas automáticamente (excluyendo link-local): {", ".join(networks)}')
        else:
            await self.log('error', 'No se especificó red a escanear')
            return

        while self.is_running:
            try:
                all_current = []
                for net, iface in scan_targets:
                    await self.log('info', f'Escaneando red {net}' + (f' con interfaz {iface}' if iface else ''))
                    loop = asyncio.get_event_loop()
                    current = await loop.run_in_executor(None, self.scan_network, net, iface, timeout)
                    all_current.extend(current)

                known = self.load_known(known_file)

                current_set = {(d['ip'], d['mac']) for d in all_current}
                known_set = {(d['ip'], d['mac']) for d in known}
                new_set = current_set - known_set
                new = [{'ip': ip, 'mac': mac} for ip, mac in new_set]
                for dev in current:
                        await self.store_data({
                            'ip': dev['ip'],
                            'mac': dev['mac'],
                            'new': dev in new  # True si es nuevo
                        })

                if new:
                    for dev in new:
                        await self.alert('new_device', 'Nuevo dispositivo detectado', dev)
                    await self.log('info', f'Nuevos dispositivos: {new}')

                self.save_known(known_file, all_current)
            except Exception as e:
                await self.log('error', f'Error en escaneo: {e}')

            await asyncio.sleep(interval)

    def _get_all_networks(self):
        """Obtiene todas las redes locales de las interfaces activas, excluyendo link-local y duplicados."""
        networks = set()
        try:
            adapters = ifaddr.get_adapters()
            for adapter in adapters:
                for ip in adapter.ips:
                    if ip.is_IPv4 and not ip.ip.startswith('127.'):
                        # Excluir redes link-local (169.254.0.0/16)
                        if ip.ip.startswith('169.254.'):
                            continue
                        network = ipaddress.IPv4Network(f"{ip.ip}/{ip.network_prefix}", strict=False)
                        networks.add(str(network))
            # Opcional: ordenar para que las redes privadas (RFC 1918) aparezcan primero
            def priority(net):
                net_obj = ipaddress.IPv4Network(net)
                if net_obj.is_private:
                    return 0  # prioridad alta
                else:
                    return 1
            return sorted(networks, key=priority)
        except Exception as e:
            self.log('error', f'Error detectando redes con ifaddr: {e}')
            return []

    def scan_network(self, ip_range, interface=None, timeout=5):
        from scapy.all import ARP, Ether, srp, conf
        old_iface = conf.iface
        try:
            if interface:
                conf.iface = interface
            arp = ARP(pdst=ip_range)
            ether = Ether(dst='ff:ff:ff:ff:ff:ff')
            answered = srp(ether/arp, timeout=timeout, verbose=False)[0]
            return [{'ip': r[1].psrc, 'mac': r[1].hwsrc} for r in answered]
        finally:
            conf.iface = old_iface

    def load_known(self, path):
        try:
            with open(path) as f:
                return json.load(f)
        except:
            return []

    def save_known(self, path, data):
        with open(path, 'w') as f:
            json.dump(data, f, indent=4)