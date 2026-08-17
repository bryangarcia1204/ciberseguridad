import json
import secrets
import os
from pathlib import Path

CONFIG_FILE = Path("data/server_config.json")
ENV_API_KEY = os.environ.get("SERVER_API_KEY")
# Lista de hashes permitidos (puede venir de variable de entorno o archivo)
ALLOWED_HASHES = os.environ.get("ALLOWED_AGENT_HASHES", "").split(",") if os.environ.get("ALLOWED_AGENT_HASHES") else []

# Redis URL
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

def get_api_key():
    """Retorna la API Key: prioridad a variable de entorno, luego archivo, o genera nueva."""
    if ENV_API_KEY:
        return ENV_API_KEY

    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
        return config["api_key"]

    # Generar nueva
    api_key = secrets.token_urlsafe(32)
    config = {"api_key": api_key}
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)
    os.chmod(CONFIG_FILE, 0o600)
    return api_key

def add_allowed_hash(agent_hash):
    """Añade un hash a la lista (para administración)."""
    if agent_hash not in ALLOWED_HASHES:
        ALLOWED_HASHES.append(agent_hash)
        # Opcional: persistir en archivo
        with open("data/allowed_hashes.txt", "a") as f: f.write(agent_hash + "\n")

def is_hash_allowed(agent_hash):
    """Verifica si un hash está permitido (si la lista está vacía, se permite todo)."""
    if not ALLOWED_HASHES:
        return True
    return agent_hash in ALLOWED_HASHES

API_KEY = get_api_key()