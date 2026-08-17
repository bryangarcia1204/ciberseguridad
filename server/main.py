# main.py
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, Depends, HTTPException, Form, Response
from fastapi.responses import StreamingResponse, HTMLResponse, JSONResponse
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from sqlalchemy.orm import Session
import asyncio
import uvicorn
import logging
import secrets
from datetime import datetime, timedelta
import pyotp
import qrcode
import io
import base64
import os
import platform
import subprocess
import json
import socket
import ipaddress
from typing import Optional, Dict, List

from orchestrator import Orchestrator
from util.logger import setup_logging
from database import SessionLocal, Agent, Event, init_db, get_db, User, UserRole, ModuleData
from websocket_manager import manager
from modules import (
    port_scanner,
    brute_forcer,
    malware_scanner,
    backup_system,
    password_manager,
)
from modules.password_manager import init_password_manager
from server_config import API_KEY, is_hash_allowed, REDIS_URL
import redis.asyncio as redis
from auth import verify_password, create_access_token, get_password_hash, verify_token, refresh_access_token, revoke_refresh_token, create_refresh_token, set_refresh_store
from util.validators import validate_host, validate_url
from util.dependencies import get_current_active_user, require_role
from util.audit import log_action
from util.schemas import AgentRegister, Command
from util.certs import ZIP_PATH, create_initial_zip, load_certs_from_zip, create_ssl_context

# ==================== NUEVAS IMPORTACIONES ====================
from util.dns_bootstrap import start_dns_bootstrap, stop_dns_bootstrap
from util.dhcp_server import start_dhcp_server, stop_dhcp_server, get_dhcp_server

# Configurar logging
setup_logging()
logger = logging.getLogger("main")

# Inicializar base de datos
init_db()

# Almacén temporal para tokens parciales (en producción usa Redis)
partial_tokens = {}

# Seguridad: API Key header y JWT bearer
api_key_header = APIKeyHeader(name="ServCybersegurity-API-Key", auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Variables globales para servicios
redis_client = None
dns_server = None
dhcp_server = None
SERVER_IP = None

# ==================== FUNCIÓN PARA DETECTAR IP DEL SERVIDOR ====================
def get_server_ip():
    """Obtiene la IP del servidor automáticamente."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

SERVER_IP = get_server_ip()
logger.info(f"IP del servidor detectada: {SERVER_IP}")

# ==================== FUNCIÓN PARA DETECTAR SUBNET ====================
def detect_subnet(ip: str) -> str:
    """Detecta la subred /24 a partir de una IP."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            network = ipaddress.ip_network(f"{ip}/24", strict=False)
            return str(network)
    except:
        pass
    return None

# ==================== ACTUALIZAR CONFIGURACIONES CON IP ====================
def update_dhcp_config():
    """Actualiza la configuración DHCP con la IP y subred del servidor."""
    config_path = "config/dhcp_server.json"
    
    # Si ya existe configuración, respetarla (el usuario la ha personalizado)
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            # Verificar si los valores son coherentes
            if config.get('subnet') and config.get('start_ip') and config.get('end_ip'):
                logger.info("✅ Configuración DHCP personalizada encontrada, respetando valores.")
                return
        except:
            pass

    # Generar configuración automática basada en la IP del servidor
    subnet = detect_subnet(SERVER_IP)
    if not subnet:
        logger.error("❌ No se pudo detectar la subred. Usando valores por defecto.")
        subnet = "192.168.1.0/24"
        base = "192.168.1"
    else:
        base = subnet.split('/')[0].rsplit('.', 1)[0]

    config = {
        "subnet": subnet,
        "start_ip": f"{base}.2",
        "end_ip": f"{base}.200",
        "gateway": SERVER_IP,
        "dns_servers": [SERVER_IP, "8.8.8.8", "1.1.1.1"],
        "domain": "ciberlab.security.lo",
        "lease_time": 86400
    }

    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=2)
    
    logger.info(f"✅ Configuración DHCP generada: subnet={subnet}, pool={config['start_ip']}-{config['end_ip']}")

def update_traffic_config():
    """Actualiza la configuración del Traffic Controller con la subred del servidor."""
    config_path = "config/traffic_controller.json"
    
    # Si ya existe configuración, respetarla
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            if config.get('local_networks'):
                logger.info("✅ Configuración Traffic Controller personalizada encontrada, respetando valores.")
                return
        except:
            pass

    # Generar configuración automática
    subnet = detect_subnet(SERVER_IP)
    if not subnet:
        logger.error("❌ No se pudo detectar la subred. Usando valores por defecto.")
        subnet = "192.168.1.0/24"

    config = {
        "local_networks": [subnet],
        "admin_port": 8433,
        "waf_http_port": 80,        # El WAF escucha en 80 por defecto
        "waf_https_port": 8443,
        "whitelist_ips": [SERVER_IP, "127.0.0.1"],
        "max_connections_per_ip": 100,
        "block_suspicious_ips": True,
        "scan_ports": True,
        "cache_ttl": 60
    }

    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=2)
    
    logger.info(f"✅ Configuración Traffic Controller generada: local_networks={subnet}")

# Actualizar configuraciones
update_dhcp_config()
update_traffic_config()

# Inicializar orquestador
orchestrator = Orchestrator()

# ==================== INICIAR SERVICIOS DNS Y DHCP ====================
def init_dns_dhcp():
    """Inicia los servicios DNS y DHCP (se ejecuta en el lifespan)."""
    global dns_server, dhcp_server
    
    # DNS Bootstrap
    try:
        dns_config_path = "config/dns_bootstrap.json"
        if os.path.exists(dns_config_path):
            with open(dns_config_path, 'r') as f:
                dns_config = json.load(f)
        else:
            dns_config = {"domain": "ciberseguridad.local", "port": 53}
        
        dns_server = start_dns_bootstrap(dns_config)
    except Exception as e:
        logger.warning(f"No se pudo iniciar DNS: {e}")
    
    # DHCP Server
    
    ENABLE_DHCP = os.environ.get("ENABLE_DHCP", "true").lower() == "true"
    if ENABLE_DHCP:
        try:
            dhcp_config_path = "config/dhcp_server.json"
            if os.path.exists(dhcp_config_path):
                with open(dhcp_config_path, 'r') as f:
                    dhcp_config = json.load(f)
            else:
                dhcp_config = {}
            
            dhcp_server = start_dhcp_server(dhcp_config)
            logger.info(f"📡 DHCP Server iniciado (Gateway: {dhcp_config.get('gateway', SERVER_IP)})")
        except Exception as e:
            logger.warning(f"No se pudo iniciar DHCP: {e}")
    else:
        logger.info("DHCP deshabilitado por configuración")
        

# ==================== INICIAR MÓDULOS AUTOMÁTICAMENTE ====================
async def start_security_modules():
    """Inicia los módulos de seguridad automáticamente."""
    # Iniciar Traffic Controller
    if 'traffic_controller' in orchestrator.modules:
        orchestrator.start_module('traffic_controller')
        logger.info('✅ Controlador de Trafico iniciado')
    else:
        logger.warning('⚠️ Traffic Controller no encontrado en módulos')
    
    # Iniciar WAF Module
    if 'waf_module' in orchestrator.modules:
        orchestrator.start_module('waf_module')
        logger.info('✅ WAF iniciado')
    else:
        logger.warning('⚠️ WAF Module no encontrado en módulos')

     # Iniciar WAF Module
    if 'packet_sniffer' in orchestrator.modules:
        orchestrator.start_module('packet_sniffer')
        logger.info('✅ Sniffer de Paquetes iniciado')
    else:
        logger.warning('⚠️ WAF Module no encontrado en módulos')
    
    await asyncio.sleep(2)

# ==================== VERIFICAR API KEY O JWT ====================
async def verify_api_key_or_jwt(
    request: Request,
    api_key: str = Depends(api_key_header),
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)
):
    """Verifica API Key, JWT en cabecera o JWT en cookie."""
    # 1. API Key
    if api_key and api_key == API_KEY:
        return {"type": "api_key"}
    # 2. Bearer token en cabecera
    if credentials:
        token = credentials.credentials
        payload = verify_token(token)
        if payload:
            return {"type": "jwt", "user": payload.get("sub")}
    # 3. Token en cookie
    cookie_token = request.cookies.get("access_token")
    if cookie_token:
        payload = verify_token(cookie_token)
        if payload:
            return {"type": "jwt", "user": payload.get("sub")}
    raise HTTPException(status_code=403, detail="No autorizado")

# ==================== CLASE PARA CONTROL DE INTENTOS ====================
class LoginAttempt:
    def __init__(self):
        self.attempts = {}

    def add_attempt(self, ip):
        now = datetime.utcnow()
        if ip not in self.attempts:
            self.attempts[ip] = []
        self.attempts[ip] = [t for t in self.attempts[ip] if t > now - timedelta(minutes=15)]
        self.attempts[ip].append(now)

    def get_recent_count(self, ip):
        now = datetime.utcnow()
        if ip not in self.attempts:
            return 0
        return len([t for t in self.attempts[ip] if t > now - timedelta(minutes=15)])

login_attempts = LoginAttempt()

# ==================== INICIALIZAR GESTOR DE CONTRASEÑAS ====================
pm = init_password_manager()
global _password_manager
_password_manager = pm

# ==================== FUNCIÓN PARA CREAR ADMIN ====================
def ensure_admin_user(db: Session):
    admin = db.query(User).filter(User.username == "admin").first()
    if not admin:
        admin_password = os.environ.get("ADMIN_PASSWORD")
        if not admin_password:
            admin_password = secrets.token_urlsafe(12)
            print(f"⚠️  ADMIN_PASSWORD no definida. Se ha generado una contraseña temporal: {admin_password}")
        hashed = get_password_hash(admin_password)
        admin_user = User(username="admin", password_hash=hashed)
        db.add(admin_user)
        db.commit()
        print("Usuario administrador creado.")

# ==================== LIFESPAN ====================
# main.py - modificar en lifespan, después de crear los módulos

@asynccontextmanager
async def lifespan(app: FastAPI):
    global redis_client
    logger.info("Iniciando servidor...")
    
    # 1. Callback de eventos
    async def combined_callback(event_type: str, data: dict):
        asyncio.create_task(orchestrator._broadcast_event(event_type, data))
        db = SessionLocal()
        event = Event(
            agent_id=0,
            type=event_type,
            level=data.get("level", "info"),
            module=data.get("module", "server"),
            message=data.get("message", ""),
            data=data.get("data", {})
        )
        db.add(event)
        db.commit()
        db.close()

    # 2. Crear usuario admin
    db = SessionLocal()
    ensure_admin_user(db)
    app.state.password_manager = _password_manager
    logger.info("Gestor de contraseñas inicializado")
    db.close()

    # 3. Configurar callbacks en módulos Y INYECTAR ORCHESTRATOR
    for mod in orchestrator.modules.values():
        mod.set_event_callback(combined_callback)
        mod._orchestrator = orchestrator  # <-- NUEVO: Inyectar orquestador para que módulos accedan a otros

    # 4. Inicializar Redis
    redis_client = None
    if REDIS_URL:
        try:
            redis_client = redis.from_url(REDIS_URL)
            await redis_client.ping()
            logger.info("Redis conectado correctamente")
        except Exception as e:
            logger.error(f"Error al conectar a Redis: {e}. Usando almacenamiento en memoria.")
    app.state.redis = redis_client
    set_refresh_store(redis_client)

    # 5. Iniciar servicios DNS y DHCP
    app.state.dns_server = dns_server
    app.state.dhcp_server = dhcp_server

    # 6. Iniciar módulos de seguridad automáticamente
    await start_security_modules()

    logger.info("Servidor iniciado. Módulos listos.")
    yield

    # ==================== SHUTDOWN ====================
    logger.info("Deteniendo módulos...")
    for mod in orchestrator.modules.values():
        await mod.stop()

    # Detener servicios
    stop_dhcp_server()
    stop_dns_bootstrap()

    if redis_client:
        await redis_client.close()

    logger.info("Servidor detenido.")

# ==================== CREAR APP ====================
app = FastAPI(title="Sistema de Ciberseguridad Central", lifespan=lifespan)
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ==================== MANEJADORES DE EXCEPCIÓN ====================
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    return JSONResponse(
        status_code=422,
        content={"detail": "Error de validación"},
    )

@app.exception_handler(Exception)
async def generic_exception_handler(request, exc):
    logger.error(f"Error interno: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Error interno del servidor"},
    )

# ==================== MIDDLEWARE ====================
@app.middleware("https")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )
    return response

# ==================== ENDPOINTS PÚBLICOS ====================
@app.post("/agents/register")
@limiter.limit("5/minute")
def register_agent(
    request: Request,
    name: str,
    hostname: str,
    ip: str,
    hash: str = None,
    db: Session = Depends(get_db)
):
    existing = db.query(Agent).filter(Agent.name == name).first()
    if existing:
        raise HTTPException(400, "Nombre de agente ya existe")
    
    if hash and not is_hash_allowed(hash):
        logger.warning(f"Intento de registro con hash no permitido: {hash} (agente {name})")
        raise HTTPException(403, "Hash de agente no autorizado")
    
    token = secrets.token_urlsafe(32)
    agent = Agent(name=name, hostname=hostname, ip=ip, token=token, status="offline")
    db.add(agent)
    db.commit()
    db.refresh(agent)
    return {"id": agent.id, "token": token}

@app.websocket("/agents/ws")
async def agent_websocket(websocket: WebSocket, db: Session = Depends(get_db)):
    client_ip = websocket.client.host
    await websocket.accept()
    try:
        data = await websocket.receive_json()
        token = data.get("token")
        if not token:
            await websocket.close(code=1008)
            return
        agent = db.query(Agent).filter(Agent.token == token).first()
        if not agent:
            await websocket.close(code=1008)
            return
    except Exception as e:
        await websocket.close(code=1008)
        return

    success = manager.add_connection(agent.id, websocket, client_ip)
    if not success:
        await websocket.close(code=1008, reason="Límite de conexiones por IP excedido")
        return

    agent.status = "online"
    agent.last_seen = datetime.utcnow()
    db.commit()

    try:
        while True:
            data = await websocket.receive_json()
            if data["type"] in ("log", "alert"):
                event = Event(
                    agent_id=agent.id,
                    type=data["type"],
                    level=data.get("level", "info"),
                    module=data.get("module", ""),
                    message=data["message"],
                    data=data.get("data", {})
                )
                db.add(event)
                db.commit()
    except WebSocketDisconnect:
        manager._remove_agent(agent.id)
        agent.status = "offline"
        db.commit()

# ==================== ENDPOINTS DE AUTENTICACIÓN ====================
@app.post("/login")
@limiter.limit("10/minute")
async def login(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    ip = get_remote_address(request)

    recent = login_attempts.get_recent_count(ip)
    if recent > 3:
        delay = min(pow(2, recent - 3), 60)
        await asyncio.sleep(delay)

    user = db.query(User).filter(User.username == username).first()

    if user and user.locked_until and user.locked_until > datetime.utcnow():
        login_attempts.add_attempt(ip)
        raise HTTPException(status_code=403, detail="Cuenta bloqueada temporalmente")

    if not user or not verify_password(password, user.password_hash):
        login_attempts.add_attempt(ip)
        if user:
            user.failed_attempts += 1
            if user.failed_attempts >= 5:
                user.locked_until = datetime.utcnow() + timedelta(minutes=15)
                user.failed_attempts = 0
            db.commit()
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")

    user.failed_attempts = 0
    user.locked_until = None
    db.commit()

    if ip in login_attempts.attempts:
        login_attempts.attempts[ip] = []

    if user.twofa_enabled:
        partial_token = secrets.token_urlsafe(32)
        partial_tokens[partial_token] = (user.id, datetime.utcnow() + timedelta(minutes=5))
        return {"requires_2fa": True, "partial_token": partial_token}

    access_token = create_access_token(data={"sub": username})
    refresh_token = create_refresh_token(data={"sub": username})
    
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=1800,
        path="/"
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600,
        path="/"
    )
    
    log_action(db, "LOGIN", user_id=user.id, request=request)
    return {"status": "ok"}

@app.post("/refresh")
async def refresh_token(
    request: Request,
    response: Response,
    refresh_token: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    token = refresh_token or request.cookies.get("refresh_token")
    if not token:
        raise HTTPException(400, "Refresh token required")
    
    new_access = refresh_access_token(token)
    if not new_access:
        raise HTTPException(401, "Invalid refresh token")
    
    response.set_cookie(
        key="access_token",
        value=new_access,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=1800,
        path="/"
    )
    return {"status": "ok"}

@app.post("/logout")
async def logout(
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    revoke_refresh_token(current_user.username)
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")
    log_action(db, "LOGOUT", user_id=current_user.id, request=request)
    return {"status": "logged out"}

@app.post("/api/2fa/verify")
async def verify_2fa_login(
    partial_token: str = Form(...),
    code: str = Form(...),
    db: Session = Depends(get_db)
):
    if partial_token not in partial_tokens:
        raise HTTPException(400, "Token inválido o expirado")
    user_id, expiry = partial_tokens[partial_token]
    if datetime.utcnow() > expiry:
        del partial_tokens[partial_token]
        raise HTTPException(400, "Token expirado")

    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.twofa_secret:
        del partial_tokens[partial_token]
        raise HTTPException(400, "Usuario no tiene 2FA configurado")

    totp = pyotp.TOTP(user.twofa_secret)
    if not totp.verify(code):
        raise HTTPException(400, "Código inválido")

    del partial_tokens[partial_token]
    access_token = create_access_token(data={"sub": user.username})
    response = JSONResponse(content={"access_token": access_token, "token_type": "bearer"})
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=1800,
        path="/"
    )
    return response

# ==================== ENDPOINTS PROTEGIDOS ====================
@app.get("/api/user/me")
async def get_current_user(
    auth_info: dict = Depends(verify_api_key_or_jwt),
    db: Session = Depends(get_db)
):
    if auth_info.get("type") != "jwt":
        raise HTTPException(403, "Se requiere autenticación JWT")
    username = auth_info.get("user")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(404, "Usuario no encontrado")
    return {
        "username": user.username,
        "twofa_enabled": user.twofa_enabled
    }

@app.post("/api/2fa/enable")
async def enable_2fa(
    auth_info: dict = Depends(verify_api_key_or_jwt),
    db: Session = Depends(get_db)
):
    if auth_info.get("type") != "jwt":
        raise HTTPException(403, "Se requiere autenticación JWT")
    username = auth_info.get("user")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(404, "Usuario no encontrado")

    if user.twofa_enabled:
        raise HTTPException(400, "2FA ya está activado")

    if not user.twofa_secret:
        secret = pyotp.random_base32()
        user.twofa_secret = secret
        db.commit()
    else:
        secret = user.twofa_secret

    uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="MiSistema")
    qr = qrcode.make(uri)
    buffered = io.BytesIO()
    qr.save(buffered, format="PNG")
    qr_base64 = base64.b64encode(buffered.getvalue()).decode()

    return {
        "secret": secret,
        "uri": uri,
        "qr": f"data:image/png;base64,{qr_base64}"
    }

@app.post("/api/2fa/confirm")
async def confirm_2fa(
    auth_info: dict = Depends(verify_api_key_or_jwt),
    code: str = Form(...),
    db: Session = Depends(get_db)
):
    print(auth_info, code)
    if auth_info.get("type") != "jwt":
        raise HTTPException(403, "Se requiere autenticación JWT")
    username = auth_info.get("user")
    user = db.query(User).filter(User.username == username).first()
    if not user or not user.twofa_secret:
        raise HTTPException(400, "2FA no está en proceso de habilitación")

    totp = pyotp.TOTP(user.twofa_secret)
    if not totp.verify(code):
        raise HTTPException(400, "Código inválido")

    user.twofa_enabled = True
    db.commit()
    return {"status": "2FA activado"}

@app.post("/api/2fa/disable")
async def disable_2fa(
    auth_info: dict = Depends(verify_api_key_or_jwt),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    if auth_info.get("type") != "jwt":
        raise HTTPException(403, "Se requiere autenticación JWT")
    username = auth_info.get("user")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(404, "Usuario no encontrado")

    if not verify_password(password, user.password_hash):
        raise HTTPException(401, "Contraseña incorrecta")

    user.twofa_enabled = False
    user.twofa_secret = None
    db.commit()
    return {"status": "2FA desactivado"}

# ==================== MÓDULOS ====================
@app.get("/api/modules", dependencies=[Depends(verify_api_key_or_jwt)])
async def list_modules():
    return orchestrator.get_all_modules_info()

@app.get("/api/modules/{name}", dependencies=[Depends(verify_api_key_or_jwt)])
async def get_module(name: str):
    info = orchestrator.get_module_info(name)
    if info is None:
        return {"error": "Módulo no encontrado"}, 404
    return info

@app.post("/api/modules/{name}/start", dependencies=[Depends(verify_api_key_or_jwt)])
async def start_module(name: str):
    if name not in orchestrator.modules:
        return {"error": "Módulo no encontrado"}, 404
    orchestrator.start_module(name)
    return {"status": "started"}

@app.post("/api/modules/{name}/stop", dependencies=[Depends(verify_api_key_or_jwt)])
async def stop_module(name: str):
    if name not in orchestrator.modules:
        return {"error": "Módulo no encontrado"}, 404
    await orchestrator.stop_module(name)
    return {"status": "stopped"}

@app.post("/api/modules/{name}/configure", dependencies=[Depends(verify_api_key_or_jwt)])
async def configure_module(
    name: str,
    config: dict,
    request: Request,
    current_user: User = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db),
    auth_info: dict = Depends(verify_api_key_or_jwt)
):
    if auth_info.get("type") == "jwt" and auth_info.get("user") != "admin":
        raise HTTPException(403, "No autorizado")
    if auth_info.get("type") == "api_key":
        pass
    if name not in orchestrator.modules:
        return {"error": "Módulo no encontrado"}, 404
    orchestrator.configure_module(name, config)
    log_action(db, "CONFIGURE_MODULE", user_id=current_user.id, resource=f"module:{name}", details=config, request=request)
    return {"status": "configured"}

@app.get("/api/ai/anomalies", dependencies=[Depends(verify_api_key_or_jwt)])
def get_ai_anomalies(limit: int = 100, db: Session = Depends(get_db)):
    alerts = db.query(Event).filter(Event.type == 'alert').order_by(Event.timestamp.desc()).limit(limit*2).all()
    anomalies = []
    for a in alerts:
        if a.data and a.data.get('type') == 'ai_anomaly':
            anomalies.append({
                "id": a.id,
                "timestamp": a.timestamp,
                "data": a.data
            })
    return anomalies[:limit]

# ==================== GESTOR DE CONTRASEÑAS ====================
@app.get("/api/passwords", dependencies=[Depends(verify_api_key_or_jwt)])
def list_passwords(request: Request, auth_info: dict = Depends(verify_api_key_or_jwt)):
    if auth_info.get("type") != "jwt":
        raise HTTPException(403, "Solo accesible desde el panel web")
    pm = request.app.state.password_manager
    return pm.list_services()

@app.get("/api/passwords/{service}", dependencies=[Depends(verify_api_key_or_jwt)])
def get_password(service: str, request: Request, auth_info: dict = Depends(verify_api_key_or_jwt)):
    if auth_info.get("type") != "jwt":
        raise HTTPException(403, "Solo accesible desde el panel web")
    pm = request.app.state.password_manager
    entry = pm.get_password(service)
    if not entry:
        raise HTTPException(404, "Servicio no encontrado")
    return entry

@app.post("/api/passwords", dependencies=[Depends(verify_api_key_or_jwt)])
def add_password(
    request: Request,
    service: str = Form(...),
    username: str = Form(...),
    password: str = Form(None),
    auth_info: dict = Depends(verify_api_key_or_jwt)
):
    if auth_info.get("type") != "jwt":
        raise HTTPException(403, "Solo accesible desde el panel web")
    pm = request.app.state.password_manager
    new_pw = pm.add_password(service, username, password)
    return {"status": "added", "service": service, "username": username, "password": new_pw if not password else None}

@app.delete("/api/passwords/{service}", dependencies=[Depends(verify_api_key_or_jwt)])
def delete_password(service: str, request: Request, auth_info: dict = Depends(verify_api_key_or_jwt)):
    if auth_info.get("type") != "jwt":
        raise HTTPException(403, "Solo accesible desde el panel web")
    pm = request.app.state.password_manager
    if pm.delete_password(service):
        return {"status": "deleted"}
    raise HTTPException(404, "Servicio no encontrado")

@app.get("/api/passwords/export", dependencies=[Depends(verify_api_key_or_jwt)])
def export_passwords(request: Request, auth_info: dict = Depends(verify_api_key_or_jwt)):
    if auth_info.get("type") != "jwt":
        raise HTTPException(403, "Solo accesible desde el panel web")
    pm = request.app.state.password_manager
    exported = pm.export_db(pm.master_password)
    return {"data": exported}

@app.post("/api/passwords/import", dependencies=[Depends(verify_api_key_or_jwt)])
def import_passwords(
    request: Request,
    data: str = Form(...),
    password: str = Form(...),
    auth_info: dict = Depends(verify_api_key_or_jwt)
):
    if auth_info.get("type") != "jwt":
        raise HTTPException(403, "Solo accesible desde el panel web")
    pm = request.app.state.password_manager
    try:
        pm.import_db(data, password)
        return {"status": "imported"}
    except Exception as e:
        raise HTTPException(400, f"Error al importar: {e}")

# ==================== TAREAS ====================
@app.get("/api/tasks/port_scan", dependencies=[Depends(verify_api_key_or_jwt)])
async def port_scan(
    host: str,
    start_port: int = 1,
    end_port: int = 1024,
    timeout: float = 1.0
):
    if not validate_host(host):
        raise HTTPException(400, "Host no permitido")
    results = await port_scanner.scan(host, start_port, end_port, timeout)
    return {"host": host, "open_ports": results}

@app.get("/api/tasks/brute_force", dependencies=[Depends(verify_api_key_or_jwt)])
async def brute_force(
    url: str,
    username_field: str,
    password_field: str,
    username: str,
    max_length: int = 4,
    delay: float = 0.5
):
    if not validate_url(url):
        raise HTTPException(400, "URL no permitida")
    result = await asyncio.to_thread(
        brute_forcer.brute_force_login,
        url, username_field, password_field, username, max_length, delay
    )
    return {"result": result}

@app.get("/api/tasks/malware_scan", dependencies=[Depends(verify_api_key_or_jwt)])
async def malware_scan(directory: str, backend: str = "auto"):
    result = await asyncio.to_thread(malware_scanner.scan_directory, directory, backend=backend)
    return {"infected": result}

@app.get("/api/tasks/backup", dependencies=[Depends(verify_api_key_or_jwt)])
async def backup(source_dir: str, backup_dir: str, encrypt: bool = True):
    result = await asyncio.to_thread(backup_system.backup_files, source_dir, backup_dir, encrypt)
    return {"message": result}

@app.get("/api/tasks/password/generate", dependencies=[Depends(verify_api_key_or_jwt)])
async def generate_password(length: int = 16):
    password = await asyncio.to_thread(password_manager.PasswordManager.generate_password, length)
    return {"password": password}

@app.get("/agents", dependencies=[Depends(verify_api_key_or_jwt)])
def list_agents(db: Session = Depends(get_db)):
    agents = db.query(Agent).all()
    return [{"id": a.id, "name": a.name, "ip": a.ip, "status": a.status, "last_seen": a.last_seen} for a in agents]

@app.get("/events", dependencies=[Depends(verify_api_key_or_jwt)])
def get_events(limit: int = 100, agent_id: int = None, db: Session = Depends(get_db)):
    query = db.query(Event).order_by(Event.timestamp.desc())
    if agent_id is not None:
        query = query.filter(Event.agent_id == agent_id)
    events = query.limit(limit).all()
    return [{"id": e.id, "agent_id": e.agent_id, "type": e.type, "level": e.level, "module": e.module, "message": e.message, "data": e.data, "timestamp": e.timestamp} for e in events]

@app.post("/agents/{agent_id}/command", dependencies=[Depends(verify_api_key_or_jwt)])
@limiter.limit("10/minute")
async def send_command(
    request: Request,
    agent_id: int,
    command: dict,
    current_user: User = Depends(require_role(UserRole.OPERATOR)),
    db: Session = Depends(get_db)
):
    redis_client = request.app.state.redis
    if redis_client:
        key = f"rate_limit:agent:{agent_id}"
        current = await redis_client.incr(key)
        if current == 1:
            await redis_client.expire(key, 60)
        if current > 5:
            raise HTTPException(status_code=429, detail="Too many commands to this agent")
    else:
        agent_command_counts = getattr(app.state, "agent_command_counts", {})
        now = datetime.utcnow()
        for aid in list(agent_command_counts.keys()):
            agent_command_counts[aid] = [t for t in agent_command_counts[aid] if t > now - timedelta(minutes=1)]
        if agent_id not in agent_command_counts:
            agent_command_counts[agent_id] = []
        if len(agent_command_counts[agent_id]) >= 5:
            raise HTTPException(status_code=429, detail="Demasiados comandos a este agente")
        agent_command_counts[agent_id].append(now)
        app.state.agent_command_counts = agent_command_counts

    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(404, "Agente no encontrado")
    await manager.send_command(agent_id, command)
    log_action(db, "SEND_COMMAND", user_id=current_user.id, agent_id=agent_id, details=command, request=request)
    return {"status": "command sent"}

# ==================== PANEL WEB Y DASHBOARD ====================
@app.get("/api/server-time", dependencies=[Depends(verify_api_key_or_jwt)])
async def server_time():
    return {"time": datetime.utcnow().isoformat() + "Z"}

@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    """Dashboard principal con botón al panel de administración."""
    try:
        with open("web/dashboard.html", "r", encoding="utf-8") as f:
            html_content = f.read()
        return HTMLResponse(content=html_content)
    except FileNotFoundError:
        logger.warning("dashboard.html no encontrado, usando versión inline")
        return HTMLResponse(content=get_inline_dashboard())

def get_inline_dashboard():
    return """
    <!DOCTYPE html>
    <html>
    <head><title>Centro de Seguridad</title></head>
    <body style="background:#1e1e2f;color:#fff;font-family:Arial;padding:40px;text-align:center;">
        <h1>🛡️ Centro de Seguridad</h1>
        <p>Dashboard no encontrado. Verifica que web/dashboard.html existe.</p>
        <a href="/panel/admin" style="color:#4CAF50;">Ir al Panel Admin</a>
    </body>
    </html>
    """

@app.get("/panel/admin", response_class=HTMLResponse)
async def admin_panel():
    """Panel de administración para controlar tráfico, DHCP y DNS."""
    try:
        with open("web/admin_panel.html", "r", encoding="utf-8") as f:
            html_content = f.read()
        return HTMLResponse(content=html_content)
    except FileNotFoundError:
        logger.warning("admin_panel.html no encontrado")
        return HTMLResponse(content="<h1>Panel Admin</h1><p>Archivo no encontrado</p>")

# ==================== ENDPOINTS TRAFFIC CONTROLLER ====================
@app.get("/api/modules/traffic_controller/stats", dependencies=[Depends(verify_api_key_or_jwt)])
async def get_traffic_stats():
    if 'traffic_controller' in orchestrator.modules:
        module = orchestrator.modules['traffic_controller']
        return module.get_stats()
    raise HTTPException(404, "Traffic Controller no disponible")

# main.py - Reemplazar endpoint de connections

@app.get("/api/modules/traffic_controller/connections", dependencies=[Depends(verify_api_key_or_jwt)])
async def get_traffic_connections(limit: int = 50):
    """
    Obtiene las últimas conexiones capturadas por el sniffer.
    """
    try:
        db = SessionLocal()
        # Obtener los últimos datos del sniffer desde ModuleData
        packets = db.query(ModuleData).filter(
            ModuleData.module == 'packet_sniffer'
        ).order_by(ModuleData.timestamp.desc()).limit(limit).all()
        
        connections = []
        for p in packets:
            data = p.data
            # Determinar acción basada en la IP (simulación)
            # En un sistema real, esto vendría del Traffic Controller
            src_ip = data.get('src_ip', '')
            dst_ip = data.get('dst_ip', '')
            protocol = data.get('protocol', 0)
            
            # Mapear protocolo a nombre
            proto_name = {
                6: 'tcp',
                17: 'udp',
                1: 'icmp',
                0: 'unknown'
            }.get(protocol, 'unknown')
            
            # Determinar puerto destino (si existe en los datos)
            dest_port = data.get('dest_port', 0)
            if not dest_port and 'port' in data:
                dest_port = data.get('port', 0)
            
            connections.append({
                'source_ip': src_ip,
                'dest_ip': dst_ip,
                'dest_port': dest_port,
                'protocol': proto_name,
                'action': 'REDIRECT_WAF',  # Por defecto, el Traffic Controller decidirá
                'state': 'active',
                'timestamp': p.timestamp.isoformat(),
                'size': data.get('size', 0)
            })
        
        db.close()
        
        # Si no hay datos del sniffer, intentar obtener del Traffic Controller
        if not connections and 'traffic_controller' in orchestrator.modules:
            module = orchestrator.modules['traffic_controller']
            cache = getattr(module, 'decision_cache', {})
            connections = [
                {
                    'source_ip': key.split(':')[0] if ':' in key else key,
                    'dest_ip': 'unknown',
                    'dest_port': 0,
                    'protocol': 'tcp',
                    'action': action.value if hasattr(action, 'value') else str(action),
                    'state': 'active'
                }
                for key, (action, _) in cache.items()
            ][:limit]
        
        return {'connections': connections, 'total': len(connections)}
        
    except Exception as e:
        logger.error(f"Error obteniendo conexiones: {e}")
        return {'connections': [], 'total': 0}

@app.get("/api/modules/traffic_controller/blocked", dependencies=[Depends(verify_api_key_or_jwt)])
async def get_traffic_blocked():
    if 'traffic_controller' in orchestrator.modules:
        module = orchestrator.modules['traffic_controller']
        return {'ips': list(getattr(module, 'blocked_ips', []))}
    raise HTTPException(404, "Traffic Controller no disponible")

@app.get("/api/modules/traffic_controller/rules", dependencies=[Depends(verify_api_key_or_jwt)])
async def get_traffic_rules():
    if 'traffic_controller' in orchestrator.modules:
        module = orchestrator.modules['traffic_controller']
        return {
            'rules': module.get_rules()
        }
    raise HTTPException(404, "Traffic Controller no disponible")

@app.post("/api/modules/traffic_controller/block", dependencies=[Depends(verify_api_key_or_jwt)])
async def block_ip_traffic(data: dict):
    ip = data.get('ip')
    reason = data.get('reason', 'Bloqueo manual')
    if not ip:
        raise HTTPException(400, "IP requerida")
    if 'traffic_controller' in orchestrator.modules:
        module = orchestrator.modules['traffic_controller']
        module.block_ip(ip, reason)
        return {'status': 'success', 'ip': ip}
    raise HTTPException(404, "Traffic Controller no disponible")

@app.post("/api/modules/traffic_controller/unblock", dependencies=[Depends(verify_api_key_or_jwt)])
async def unblock_ip_traffic(data: dict):
    ip = data.get('ip')
    if not ip:
        raise HTTPException(400, "IP requerida")
    if 'traffic_controller' in orchestrator.modules:
        module = orchestrator.modules['traffic_controller']
        module.unblock_ip(ip)
        return {'status': 'success', 'ip': ip}
    raise HTTPException(404, "Traffic Controller no disponible")

@app.post("/api/modules/traffic_controller/rule", dependencies=[Depends(verify_api_key_or_jwt)])
async def add_traffic_rule(
    data: dict,
    current_user: User = Depends(require_role(UserRole.ADMIN))
):
    """Añade una regla de tráfico (solo admin)."""
    from modules.traffic_controller import FirewallRule, RuleAction
    
    try:
        name = data.get('name')
        source_ip = data.get('source_ip', 'any')
        dest_ip = data.get('dest_ip', 'any')
        dest_port = data.get('dest_port', 0)
        action_str = data.get('action', 'BLOCK')
        protocol = data.get('protocol', 'tcp')
        description = data.get('description', '')
        
        action = RuleAction(action_str.lower())
        
        rule = FirewallRule(
            id=0,
            name=name,
            action=action,
            source_ip=source_ip,
            dest_ip=dest_ip,
            dest_port=dest_port,
            protocol=protocol,
            enabled=True,
            priority=5,
            description=description
        )
        
        if 'traffic_controller' in orchestrator.modules:
            module = orchestrator.modules['traffic_controller']
            rule_id = module.add_rule(rule)
            return {'status': 'success', 'rule_id': rule_id}
        else:
            raise HTTPException(404, "Traffic Controller no disponible")
    except Exception as e:
        raise HTTPException(400, f"Error añadiendo regla: {str(e)}")

@app.delete("/api/modules/traffic_controller/rule/{rule_id}", dependencies=[Depends(verify_api_key_or_jwt)])
async def delete_traffic_rule(
    rule_id: int,
    current_user: User = Depends(require_role(UserRole.ADMIN))
):
    """Elimina una regla (solo admin)."""
    if 'traffic_controller' in orchestrator.modules:
        module = orchestrator.modules['traffic_controller']
        if module.remove_rule(rule_id):
            return {'status': 'success'}
        else:
            raise HTTPException(404, "Regla no encontrada")
    raise HTTPException(404, "Traffic Controller no disponible")

@app.post("/api/modules/traffic_controller/rule/{rule_id}/toggle", dependencies=[Depends(verify_api_key_or_jwt)])
async def toggle_traffic_rule(
    rule_id: int,
    data: dict,
    current_user: User = Depends(require_role(UserRole.ADMIN))
):
    """Habilita o deshabilita una regla (solo admin)."""
    enabled = data.get('enabled', True)
    if 'traffic_controller' in orchestrator.modules:
        module = orchestrator.modules['traffic_controller']
        if enabled:
            success = module.enable_rule(rule_id)
        else:
            success = module.disable_rule(rule_id)
        if success:
            return {'status': 'success'}
        else:
            raise HTTPException(404, "Regla no encontrada")
    raise HTTPException(404, "Traffic Controller no disponible")

# ==================== ENDPOINTS FIREWALL NATIVO ====================

@app.get("/api/firewall/rules", dependencies=[Depends(verify_api_key_or_jwt)])
async def get_firewall_rules():
    """
    Obtiene las reglas del firewall nativo del sistema.
    Soporta Windows (netsh) y Linux (iptables).
    """
    system = platform.system()
    rules = []
    
    try:
        if system == 'Windows':
            # Obtener reglas de Windows Firewall
            result = subprocess.run(
                'netsh advfirewall firewall show rule name=all',
                shell=True, capture_output=True, text=True
            )
            if result.returncode == 0:
                rules = _parse_windows_firewall_rules(result.stdout)
            else:
                raise HTTPException(500, "Error obteniendo reglas de Windows Firewall")
        
        elif system == 'Linux':
            # Obtener reglas de iptables
            result = subprocess.run(
                'iptables -L -n -v --line-numbers',
                shell=True, capture_output=True, text=True
            )
            if result.returncode == 0:
                rules = _parse_linux_iptables_rules(result.stdout)
            else:
                raise HTTPException(500, "Error obteniendo reglas de iptables")
        
        else:
            raise HTTPException(500, f"Sistema {system} no soportado")
        
        return {
            'system': system,
            'rules': rules,
            'total': len(rules)
        }
    
    except Exception as e:
        logger.error(f"Error obteniendo reglas del firewall: {e}")
        raise HTTPException(500, str(e))

@app.get("/api/firewall/status", dependencies=[Depends(verify_api_key_or_jwt)])
async def get_firewall_status():
    """
    Obtiene el estado del firewall nativo (Windows/Linux).
    """
    system = platform.system()
    try:
        if system == 'Windows':
            result = subprocess.run(
                'netsh advfirewall show allprofiles state',
                shell=True, capture_output=True, text=True
            )
            if result.returncode == 0:
                # Parsear estado
                lines = result.stdout.split('\n')
                profiles = {}
                for line in lines:
                    if 'Perfil' in line and 'Estado' in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            profile = parts[0].strip().replace('Perfil', '').strip()
                            state = parts[1].strip()
                            profiles[profile] = state == 'Activado' or state == 'On'
                return {
                    'status': 'running',
                    'profiles': profiles,
                    'system': system,
                    'is_enabled': any(profiles.values()) if profiles else False
                }
            else:
                return {'status': 'error', 'message': result.stderr}
        
        elif system == 'Linux':
            # En Linux, verificar iptables status
            result = subprocess.run(
                'systemctl status iptables 2>/dev/null || service iptables status 2>/dev/null || echo "unknown"',
                shell=True, capture_output=True, text=True
            )
            is_enabled = 'active' in result.stdout.lower() or 'running' in result.stdout.lower()
            return {
                'status': 'running',
                'is_enabled': is_enabled,
                'system': system
            }
        
        else:
            return {'status': 'error', 'message': f'Sistema {system} no soportado'}
    
    except Exception as e:
        logger.error(f"Error obteniendo estado del firewall: {e}")
        return {'status': 'error', 'message': str(e)}

@app.post("/api/firewall/toggle", dependencies=[Depends(verify_api_key_or_jwt)])
async def toggle_firewall(
    data: dict,
    current_user: User = Depends(require_role(UserRole.ADMIN))
):
    """
    Activa o desactiva el firewall nativo.
    """
    system = platform.system()
    enable = data.get('enable', True)
    
    try:
        if system == 'Windows':
            state = 'on' if enable else 'off'
            # Aplicar a todos los perfiles
            cmd = f'netsh advfirewall set allprofiles state {state}'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                raise HTTPException(400, f"Error: {result.stderr}")
            return {'status': 'success', 'enabled': enable}
        
        elif system == 'Linux':
            if enable:
                cmd = 'systemctl start iptables 2>/dev/null || service iptables start 2>/dev/null'
            else:
                cmd = 'systemctl stop iptables 2>/dev/null || service iptables stop 2>/dev/null'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return {'status': 'success', 'enabled': enable}
        
        else:
            raise HTTPException(500, f"Sistema {system} no soportado")
    
    except Exception as e:
        logger.error(f"Error toggleando firewall: {e}")
        raise HTTPException(500, str(e))
    
# ==================== ENDPOINT PARA LAS REGLAS DEL FIREWALL ====================

@app.post("/api/firewall/rule/toggle", dependencies=[Depends(verify_api_key_or_jwt)])
async def toggle_firewall_rule(
    data: dict,
    current_user: User = Depends(require_role(UserRole.ADMIN))
):
    """
    Activa o desactiva una regla del firewall nativo.
    """
    system = platform.system()
    rule_name = data.get('name')
    enable = data.get('enable', True)
    
    if not rule_name:
        raise HTTPException(400, "Nombre de regla requerido")
    
    try:
        if system == 'Windows':
            enable_str = 'yes' if enable else 'no'
            cmd = f'netsh advfirewall firewall set rule name="{rule_name}" new enable={enable_str}'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                raise HTTPException(400, f"Error: {result.stderr}")
            return {'status': 'success', 'name': rule_name, 'enabled': enable}
        
        else:
            raise HTTPException(500, f"Sistema {system} no soportado para toggle de reglas")
    
    except Exception as e:
        logger.error(f"Error toggleando regla: {e}")
        raise HTTPException(500, str(e))

@app.post("/api/firewall/rule/advanced", dependencies=[Depends(verify_api_key_or_jwt)])
async def add_firewall_rule_advanced(
    data: dict,
    current_user: User = Depends(require_role(UserRole.ADMIN))
):
    """
    Añade una regla avanzada al firewall nativo con todos los parámetros disponibles.
    """
    system = platform.system()
    try:
        if system == 'Windows':
            cmd = _build_windows_rule_command(data)
            logger.info(f"Ejecutando comando: {cmd}")
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                raise HTTPException(400, f"Error añadiendo regla: {result.stderr}")
            return {'status': 'success', 'message': 'Regla añadida correctamente'}
        
        elif system == 'Linux':
            cmd = _build_linux_rule_command(data)
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                raise HTTPException(400, f"Error añadiendo regla: {result.stderr}")
            return {'status': 'success', 'message': 'Regla añadida correctamente'}
        
        else:
            raise HTTPException(500, f"Sistema {system} no soportado")
    
    except Exception as e:
        logger.error(f"Error añadiendo regla avanzada: {e}")
        raise HTTPException(500, str(e))
    
@app.delete("/api/firewall/rule/{rule_id}", dependencies=[Depends(verify_api_key_or_jwt)])
async def delete_firewall_rule(
    rule_id: str,
    current_user: User = Depends(require_role(UserRole.ADMIN))
):
    """
    Elimina una regla del firewall nativo.
    """
    system = platform.system()
    try:
        if system == 'Windows':
            cmd = f'netsh advfirewall firewall delete rule name="{rule_id}"'
        elif system == 'Linux':
            # iptables elimina por línea (número)
            cmd = f'iptables -D INPUT {rule_id}'
        else:
            raise HTTPException(500, f"Sistema {system} no soportado")
        
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            raise HTTPException(400, f"Error eliminando regla: {result.stderr}")
        
        return {'status': 'success', 'message': 'Regla eliminada correctamente'}
    
    except Exception as e:
        logger.error(f"Error eliminando regla del firewall: {e}")
        raise HTTPException(500, str(e))

# ==================== FUNCIONES AUXILIARES ====================

def _parse_windows_firewall_rules(output: str) -> List[Dict]:
    """
    Parsea la salida de 'netsh advfirewall firewall show rule name=all'.
    """
    rules = []
    current_rule = {}
    lines = output.split('\n')
    
    for line in lines:
        line = line.strip()
        
        # Saltar líneas de separación
        if line.startswith('---') or line.startswith('==='):
            continue
        
        # Si encontramos "Nombre de regla:" o "Rule Name:", guardamos la regla anterior
        if line.startswith('Nombre de regla:') or line.startswith('Rule Name:'):
            if current_rule:
                rules.append(current_rule)
                current_rule = {}
            
            # Extraer el nombre de la regla
            name_part = line.split(':', 1)[1].strip()
            # Si hay un espacio después del nombre, lo mantenemos
            current_rule['name'] = name_part
            continue
        
        # Parsear campos clave-valor
        if ':' in line:
            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip()
            
            # Mapear nombres de campos en español/inglés a nombres consistentes
            field_map = {
                'Habilitada': 'enabled',
                'Enabled': 'enabled',
                'Dirección': 'direction',
                'Direction': 'direction',
                'Acción': 'action',
                'Action': 'action',
                'Protocolo': 'protocol',
                'Protocol': 'protocol',
                'LocalIP': 'local_ip',
                'RemoteIP': 'remote_ip',
                'LocalPort': 'local_port',
                'RemotePort': 'remote_port',
                'Perfiles': 'profiles',
                'Profiles': 'profiles',
                'Agrupamiento': 'grouping',
                'Grouping': 'grouping',
                'Cruce seguro del perímetro': 'secure_edge',
                'Nombre de regla': 'name',
                'Rule Name': 'name'
            }
            
            # Usar el mapeo o el nombre original
            field_name = field_map.get(key, key)
            
            # Convertir valores booleanos
            if field_name == 'enabled':
                current_rule[field_name] = value.lower() in ('sí', 'yes', 'true', '1')
            else:
                current_rule[field_name] = value
    
    # Añadir la última regla
    if current_rule:
        rules.append(current_rule)
    
    return rules

def _parse_linux_iptables_rules(output: str) -> List[Dict]:
    """Parsea la salida de 'iptables -L -n -v --line-numbers'."""
    rules = []
    lines = output.split('\n')
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('Chain') or line.startswith('pkts'):
            continue
        
        parts = line.split()
        if len(parts) >= 7:
            rule = {
                'num': parts[0],
                'pkts': parts[1],
                'bytes': parts[2],
                'target': parts[3],
                'prot': parts[4],
                'in': parts[5] if len(parts) > 5 else '*',
                'out': parts[6] if len(parts) > 6 else '*',
                'source': parts[7] if len(parts) > 7 else '0.0.0.0/0',
                'destination': parts[8] if len(parts) > 8 else '0.0.0.0/0',
                'full': line
            }
            rules.append(rule)
    
    return rules

def _build_windows_rule_command(data: dict) -> str:
    """
    Construye comando netsh para Windows con todos los parámetros posibles.
    """
    name = data.get('name', 'ReglaCyberSec')
    dir_param = data.get('dir', 'in')
    action = data.get('action', 'block')

    cmd = f'netsh advfirewall firewall add rule name="{name}" dir={dir_param} action={action}'

    # Opciones comunes
    if data.get('program'):
        cmd += f' program="{data["program"]}"'
    if data.get('service'):
        cmd += f' service={data["service"]}'
    if data.get('description'):
        cmd += f' description="{data["description"]}"'
    if data.get('enable'):
        cmd += f' enable={data["enable"]}'
    if data.get('profile'):
        cmd += f' profile={data["profile"]}'
    if data.get('protocol'):
        cmd += f' protocol={data["protocol"]}'
    if data.get('localport'):
        cmd += f' localport={data["localport"]}'
    if data.get('remoteport'):
        cmd += f' remoteport={data["remoteport"]}'
    if data.get('localip'):
        cmd += f' localip={data["localip"]}'
    if data.get('remoteip'):
        cmd += f' remoteip={data["remoteip"]}'
    if data.get('interfacetype'):
        cmd += f' interfacetype={data["interfacetype"]}'

    # Opciones avanzadas
    if data.get('edge') is not None:
        cmd += f' edge={data["edge"]}'
    if data.get('security'):
        cmd += f' security={data["security"]}'
    if data.get('rmtcomputergrp'):
        cmd += f' rmtcomputergrp={data["rmtcomputergrp"]}'
    if data.get('rmtusrgrp'):
        cmd += f' rmtusrgrp={data["rmtusrgrp"]}'

    return cmd

def _build_linux_rule_command(action: str, source_ip: str, dest_ip: str, 
                              dest_port: str, protocol: str) -> str:
    """Construye comando iptables para Linux."""
    cmd = f'iptables -A INPUT'
    
    if source_ip != 'any':
        cmd += f' -s {source_ip}'
    if dest_ip != 'any':
        cmd += f' -d {dest_ip}'
    if dest_port != 'any':
        cmd += f' --dport {dest_port}'
    if protocol != 'any':
        cmd += f' -p {protocol}'
    
    if action == 'allow':
        cmd += ' -j ACCEPT'
    else:
        cmd += ' -j DROP'
    
    return cmd

# ==================== ENDPOINTS SNIFFER ====================
@app.get("/api/modules/packet_sniffer/stats", dependencies=[Depends(verify_api_key_or_jwt)])
async def get_sniffer_stats():
    """Obtiene estadísticas del Packet Sniffer."""
    if 'packet_sniffer' in orchestrator.modules:
        db = SessionLocal()
        try:
            since = datetime.utcnow() - timedelta(minutes=10)
            count = db.query(ModuleData).filter(
                ModuleData.module == 'packet_sniffer',
                ModuleData.timestamp >= since
            ).count()
            return {
                'status': 'running',
                'packets_last_5min': count,
                'total_packets': count
            }
        finally:
            db.close()
    return {'status': 'stopped', 'packets_last_5min': 0}

@app.get("/api/modules/packet_sniffer/packets", dependencies=[Depends(verify_api_key_or_jwt)])
async def get_sniffer_packets(limit: int = 50):
    """Obtiene los últimos paquetes capturados."""
    if 'packet_sniffer' in orchestrator.modules:
        db = SessionLocal()
        try:
            packets = db.query(ModuleData).filter(
                ModuleData.module == 'packet_sniffer'
            ).order_by(ModuleData.timestamp.desc()).limit(limit).all()
            return {
                'packets': [
                    {
                        'timestamp': p.timestamp.isoformat(),
                        'data': p.data
                    }
                    for p in packets
                ],
                'count': len(packets)
            }
        finally:
            db.close()
    return {'packets': [], 'count': 0}

@app.get("/api/sniffer/realtime", dependencies=[Depends(verify_api_key_or_jwt)])
async def get_sniffer_realtime(limit: int = 20):
    """
    Obtiene los últimos paquetes capturados en tiempo real.
    """
    try:
        db = SessionLocal()
        packets = db.query(ModuleData).filter(
            ModuleData.module == 'packet_sniffer'
        ).order_by(ModuleData.timestamp.desc()).limit(limit).all()
        
        result = []
        for p in packets:
            data = p.data
            proto = data.get('protocol', 0)
            proto_name = {
                6: 'TCP',
                17: 'UDP',
                1: 'ICMP',
                0: 'UNKNOWN'
            }.get(proto, 'UNKNOWN')
            
            result.append({
                'timestamp': p.timestamp.isoformat(),
                'src_ip': data.get('src_ip', ''),
                'dst_ip': data.get('dst_ip', ''),
                'src_port': data.get('src_port', 0),
                'dst_port': data.get('dest_port', 0),
                'protocol': proto_name,
                'size': data.get('size', 0)
            })
        
        db.close()
        return {'packets': result, 'count': len(result)}
    except Exception as e:
        logger.error(f"Error obteniendo datos del sniffer: {e}")
        return {'packets': [], 'count': 0}

# ==================== ENDPOINTS DHCP ====================
@app.get("/api/dhcp/stats", dependencies=[Depends(verify_api_key_or_jwt)])
async def get_dhcp_stats():
    server = get_dhcp_server()
    if not server:
        raise HTTPException(500, "DHCP Server no disponible")
    stats = server.get_stats()
    stats['gateway'] = getattr(server, 'gateway', SERVER_IP)
    stats['dns_servers'] = getattr(server, 'dns_servers', [])
    return stats

@app.get("/api/dhcp/leases", dependencies=[Depends(verify_api_key_or_jwt)])
async def get_dhcp_leases():
    server = get_dhcp_server()
    if not server:
        raise HTTPException(500, "DHCP Server no disponible")
    leases = server.get_active_leases()
    return {
        'total': len(leases),
        'devices': [
            {
                'ip': lease.ip,
                'mac': lease.mac,
                'hostname': lease.hostname or 'Desconocido',
                'expires_in': int((lease.end_time - datetime.now()).total_seconds()),
                'connected_at': lease.start_time.isoformat()
            }
            for lease in leases
        ]
    }

# ==================== ENDPOINTS DNS ====================
@app.get("/api/dns/status", dependencies=[Depends(verify_api_key_or_jwt)])
async def get_dns_status():
    from util.dns_bootstrap import _dns_server
    if _dns_server and _dns_server.running:
        return {
            'status': 'running',
            'domain': _dns_server.domain,
            'resolution': _dns_server.local_ip,
            'blocked_domains': getattr(_dns_server, 'blocked_domains', [])
        }
    return {'status': 'stopped', 'domain': 'ciberseguridad.local'}

@app.post("/api/dns/block", dependencies=[Depends(verify_api_key_or_jwt)])
async def block_dns_domain(data: dict):
    domain = data.get('domain')
    if not domain:
        raise HTTPException(400, "Dominio requerido")
    from util.dns_bootstrap import _dns_server
    if _dns_server and _dns_server.running:
        if not hasattr(_dns_server, 'blocked_domains'):
            _dns_server.blocked_domains = []
        if domain not in _dns_server.blocked_domains:
            _dns_server.blocked_domains.append(domain)
            return {'status': 'success', 'domain': domain}
        return {'status': 'error', 'message': 'Dominio ya bloqueado'}
    raise HTTPException(404, "DNS no disponible")

@app.post("/api/dns/unblock", dependencies=[Depends(verify_api_key_or_jwt)])
async def unblock_dns_domain(data: dict):
    domain = data.get('domain')
    if not domain:
        raise HTTPException(400, "Dominio requerido")
    from util.dns_bootstrap import _dns_server
    if _dns_server and _dns_server.running:
        if hasattr(_dns_server, 'blocked_domains') and domain in _dns_server.blocked_domains:
            _dns_server.blocked_domains.remove(domain)
            return {'status': 'success', 'domain': domain}
        return {'status': 'error', 'message': 'Dominio no encontrado en lista de bloqueo'}
    raise HTTPException(404, "DNS no disponible")

@app.post("/api/dns/record", dependencies=[Depends(verify_api_key_or_jwt)])
async def add_dns_record(data: dict):
    zone = data.get('zone')
    record_type = data.get('type')
    name = data.get('name')
    value = data.get('value')
    if not all([zone, record_type, name, value]):
        raise HTTPException(400, "Todos los campos son requeridos")
    logger.info(f"DNS Record: {zone} {record_type} {name} -> {value}")
    return {'status': 'success'}

# ==================== MAIN ====================
if __name__ == "__main__":
    # Inicializar base de datos
    init_db()

    # Gestionar certificados
    if not os.path.exists(ZIP_PATH):
        print("Generando certificados iniciales...")
        password = create_initial_zip(pm)
        print("Certificados generados y protegidos en:", ZIP_PATH)
        print("Contraseña guardada en el gestor de contraseñas.")
        certs = load_certs_from_zip(pm)
    else:
        certs = load_certs_from_zip(pm)

    # Obtener rutas de archivos SSL
    ssl_config = create_ssl_context(certs)

     # Iniciar servicios DNS y DHCP
    init_dns_dhcp()

    # Mostrar información de red al iniciar
    print("\n" + "=" * 70)
    print("🛡️  SERVIDOR DE CIBERSEGURIDAD")
    print("=" * 70)
    print(f"   IP del servidor: {SERVER_IP}")
    print(f"   Puerto HTTPS: 8433")
    print(f"   Dominio: ciberlab.security.lo")
    print(f"   DNS: {'ACTIVO' if dns_server and dns_server.running else 'INACTIVO'}")
    print(f"   DHCP: {'ACTIVO' if dhcp_server and dhcp_server.running else 'INACTIVO'}")
    print("=" * 70)
    print(f"   Acceso web: https://{SERVER_IP}:8433")
    print(f"   Acceso dominio: https://ciberlab.security.lo:8433")
    print("=" * 70 + "\n")

    # Crear configuración de uvicorn con los archivos SSL
    config = uvicorn.Config(
        "main:app",
        host="0.0.0.0",
        port=8433,
        log_level="info",
        ssl_keyfile=ssl_config['ssl_keyfile'],
        ssl_certfile=ssl_config['ssl_certfile'],
        ssl_ca_certs=ssl_config['ssl_ca_certs'],
        ssl_cert_reqs=0  # 0 = ssl.CERT_NONE (para pruebas)
    )
    server = uvicorn.Server(config)
    server.run()