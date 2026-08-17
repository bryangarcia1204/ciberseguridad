import asyncio
import re
import ssl
import ipaddress
import socket
import html
from urllib.parse import urlparse, unquote
from modules.module_base import Module
from aiohttp import web, ClientSession, TCPConnector, ClientTimeout

class WAFModule(Module):
    async def run(self):
        host = self.config.get('host', '0.0.0.0')
        port = self.config.get('port', 8080)
        default_backend = self.config.get('default_backend')
        backends = self.config.get('backends', {})
        backend_verify_ssl = self.config.get('backend_verify_ssl', True)
        backend_timeout = self.config.get('backend_timeout', 30)
        allowed_backend_ips = self.config.get('allowed_backend_ips', ['127.0.0.1', '::1', '192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12'])
        ssl_certfile = self.config.get('ssl_certfile')
        ssl_keyfile = self.config.get('ssl_keyfile')
        
        # Configuración de reglas
        enable_sqli = self.config.get('enable_sqli', True)
        enable_xss = self.config.get('enable_xss', True)
        enable_path_traversal = self.config.get('enable_path_traversal', True)
        enable_cmd_injection = self.config.get('enable_cmd_injection', False)  # Opcional

        # Patrones de ataque
        self.patterns = []

        if enable_sqli:
            self.patterns.extend([
                re.compile(r"(\%27)|(\')|(\-\-)|(\%23)|(#)", re.IGNORECASE),
                re.compile(r"(union|select|insert|drop|delete|update|alter|create|where)", re.IGNORECASE),
            ])
        
        if enable_xss:
            self.patterns.extend([
                # Etiquetas HTML/XML
                re.compile(r"<[^>]*script[^>]*>", re.IGNORECASE),
                re.compile(r"<[^>]*iframe[^>]*>", re.IGNORECASE),
                re.compile(r"<[^>]*object[^>]*>", re.IGNORECASE),
                re.compile(r"<[^>]*embed[^>]*>", re.IGNORECASE),
                re.compile(r"<[^>]*applet[^>]*>", re.IGNORECASE),
                # Eventos JavaScript
                re.compile(r"on\w+\s*=", re.IGNORECASE),
                # Protocolos javascript: en atributos
                re.compile(r"href\s*=\s*['\"]?\s*javascript:", re.IGNORECASE),
                re.compile(r"src\s*=\s*['\"]?\s*javascript:", re.IGNORECASE),
                re.compile(r"data\s*=\s*['\"]?\s*javascript:", re.IGNORECASE),
                # Expresiones de JavaScript
                re.compile(r"javascript\s*:", re.IGNORECASE),
                re.compile(r"vbscript\s*:", re.IGNORECASE),
                re.compile(r"expression\s*\(", re.IGNORECASE),
                # Función eval
                re.compile(r"eval\s*\(", re.IGNORECASE),
            ])
        
        if enable_path_traversal:
            self.patterns.append(re.compile(r"\.\./|\.\.\\", re.IGNORECASE))
        
        if enable_cmd_injection:
            self.patterns.extend([
                re.compile(r"[;&|`$]", re.IGNORECASE),
                re.compile(r"cmd\.exe|powershell", re.IGNORECASE),
            ])

        # Validar backends
        loop = asyncio.get_event_loop()
        if default_backend:
            await self._validate_backend_url(default_backend, allowed_backend_ips, loop)
        for name, url in backends.items():
            await self._validate_backend_url(url, allowed_backend_ips, loop)

        async def handle(request):
            # Analizar URL
            path = request.path_qs
            normalized_path = unquote(path)  # decodificar %xx

            # Analizar cuerpo si existe
            body = None
            if request.method in ('POST', 'PUT', 'PATCH'):
                try:
                    body = await request.text()
                except:
                    pass

            # Verificar patrones maliciosos
            if self.is_malicious(normalized_path, body):
                await self.store_data({
                    'path': path,
                    'method': request.method,
                    'host': request.headers.get('Host', '').split(':')[0],
                    'blocked': True
                })
                await self.alert('waf_block', f'Petición maliciosa bloqueada: {path}', {'path': path, 'method': request.method})
                return web.Response(status=403, text="Acceso denegado por el WAF")

            # No malicioso
            await self.store_data({
                'path': path,
                'method': request.method,
                'host': request.headers.get('Host', '').split(':')[0],
                'blocked': False
            })

            # Determinar backend
            host_header = request.headers.get('Host', '').split(':')[0]
            request_path = request.path
            backend = default_backend

            if host_header in backends:
                backend = backends[host_header]
            else:
                for prefix, target in backends.items():
                    if prefix.startswith('/') and request_path.startswith(prefix):
                        backend = target
                        break

            if not backend:
                await self.log('error', 'No se encontró backend para la petición')
                return web.Response(status=502, text="Backend no configurado")

            # Construir URL completa
            target_url = backend.rstrip('/') + path

            # Configurar timeout y SSL
            timeout = ClientTimeout(total=backend_timeout)
            connector = None
            if target_url.startswith('https') and not backend_verify_ssl:
                connector = TCPConnector(ssl=False)

            # Reenviar la petición
            async with ClientSession(connector=connector, timeout=timeout) as session:
                try:
                    async with session.request(
                        request.method,
                        target_url,
                        headers=request.headers,
                        data=await request.read()
                    ) as resp:
                        body = await resp.read()
                        return web.Response(status=resp.status, body=body, headers=resp.headers)
                except asyncio.TimeoutError:
                    await self.log('error', f'Timeout conectando con backend: {target_url}')
                    return web.Response(status=504, text="Timeout del backend")
                except Exception as e:
                    await self.log('error', f'Error al conectar con backend: {e}')
                    return web.Response(status=502, text="Error del backend")

        app = web.Application()
        app.router.add_route('*', '/{path:.*}', handle)
        runner = web.AppRunner(app)
        await runner.setup()

        ssl_context = None
        if ssl_certfile and ssl_keyfile:
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(ssl_certfile, ssl_keyfile)

        try:
            site = web.TCPSite(runner, host, port, ssl_context=ssl_context)
            await site.start()
            actual_port = port
        except OSError as e:
            if port != 0:
                await self.log('warning', f'Puerto {port} ocupado, intentando con puerto automático')
                try:
                    site = web.TCPSite(runner, host, 0, ssl_context=ssl_context)
                    await site.start()
                    actual_port = site.port
                except Exception as e2:
                    await self.log('error', f'No se pudo iniciar el WAF: {e2}')
                    await runner.cleanup()
                    return
            else:
                await self.log('error', f'Error al iniciar WAF: {e}')
                await runner.cleanup()
                return

        protocol = "https" if ssl_context else "http"
        await self.log('info', f'WAF ejecutándose en {protocol}://{host}:{actual_port}')

        try:
            while self.is_running:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            await runner.cleanup()
            raise
        finally:
            await runner.cleanup()

    async def _validate_backend_url(self, url, allowed_ips, loop):
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            raise ValueError(f"URL de backend inválida: {url}")

        try:
            ip = ipaddress.ip_address(host)
            ips = [ip]
        except ValueError:
            try:
                addrs = await loop.run_in_executor(None, socket.getaddrinfo, host, None)
                ips = {addr[4][0] for addr in addrs if addr[0] == socket.AF_INET}
            except Exception as e:
                raise ValueError(f"No se pudo resolver el dominio {host}: {e}")

        for ip in ips:
            allowed = False
            for net in allowed_ips:
                try:
                    if ip in ipaddress.ip_network(net, strict=False):
                        allowed = True
                        break
                except ValueError:
                    continue
            if not allowed:
                raise ValueError(f"IP {ip} (resuelta de {host}) no está en la lista permitida")

    def is_malicious(self, path, body=None):
        """Verifica si la petición contiene patrones maliciosos en la URL o el cuerpo."""
        # Analizar URL
        for pattern in self.patterns:
            if pattern.search(path):
                return True
        
        # Analizar cuerpo
        if body:
            for pattern in self.patterns:
                if pattern.search(body):
                    return True
        
        return False