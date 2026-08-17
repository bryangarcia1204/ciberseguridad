import asyncio
import logging
from modules.module_base import Module

class HoneypotModule(Module):
    async def run(self):
        host = self.config.get('host', '0.0.0.0')
        port = self.config.get('port', 0)
        service = self.config.get('service', 'tcp')  # 'tcp', 'http', 'ssh'
        banner = self.config.get('banner', 'Bienvenido al servidor falso\n')
        log_payload = self.config.get('log_payload', True)
        tarpit = self.config.get('tarpit', False)  # si True, retrasa las respuestas

        async def handle_client(reader, writer):
            addr = writer.get_extra_info('peername')
            client_ip = addr[0]
            client_port = addr[1]
            await self.store_data({
                'ip': client_ip,
                'port': client_port,
                'service': service
            })
            
            # Alertar conexión
            await self.alert('honeypot_connection', 'Conexión entrante',
                             {'ip': client_ip, 'port': client_port, 'service': service})
            await self.log('info', f'Conexión desde {client_ip}:{client_port}')

            # Enviar banner
            writer.write(banner.encode())
            await writer.drain()

            # Leer datos si es necesario
            if service in ('http', 'ssh') or log_payload:
                try:
                    data = await asyncio.wait_for(reader.read(4096), timeout=5)
                    if data:
                        await self.log('info', f'Datos recibidos ({len(data)} bytes)')
                        # Guardar payload en archivo (opcional)
                        if log_payload:
                            filename = f"logs/honeylog/honeypot_{client_ip}_{client_port}_{asyncio.get_event_loop().time()}.bin"
                            with open(filename, 'wb') as f:
                                f.write(data)
                            await self.log('info', f'Payload guardado en {filename}')
                        # Si es HTTP, podemos analizar cabeceras
                        if service == 'http':
                            try:
                                text = data.decode('utf-8', errors='ignore')
                                lines = text.split('\n')
                                if lines:
                                    first_line = lines[0]
                                    await self.log('info', f'HTTP request: {first_line}')
                                    # Buscar cabeceras de proxy
                                    for line in lines:
                                        if line.lower().startswith('x-forwarded-for'):
                                            forwarded = line.split(':', 1)[1].strip()
                                            await self.log('warning', f'Posible IP real en X-Forwarded-For: {forwarded}')
                                            await self.alert('honeypot_proxy', 'IP real detectada por cabecera', 
                                                             {'forwarded': forwarded, 'client_ip': client_ip})
                            except Exception as e:
                                await self.log('error', f'Error analizando HTTP: {e}')
                except asyncio.TimeoutError:
                    pass
                except Exception as e:
                    await self.log('error', f'Error leyendo datos: {e}')

            # Si tarpit está activado, retrasar la respuesta
            if tarpit:
                await asyncio.sleep(10)  # retraso fijo, podría ser exponencial

            writer.close()
            await writer.wait_closed()

        # Iniciar servidor
        server = await asyncio.start_server(handle_client, host, port)
        actual_port = server.sockets[0].getsockname()[1]
        await self.log('info', f'Honeypot {service} escuchando en {host}:{actual_port}')

        try:
            async with server:
                await server.serve_forever()
        except asyncio.CancelledError:
            await self.log('info', 'Honeypot detenido')
            server.close()
            await server.wait_closed()