import logging
import logging.handlers
import os
import sys
import re
from pathlib import Path

# Directorio de logs
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

# Formato del log
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Nivel por defecto (se puede cambiar con variable de entorno)
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# Patrones de información sensible a sanitizar
SENSITIVE_PATTERNS = [
    (r'token[=:]\s*([a-zA-Z0-9_\-]+)', r'token=***'),
    (r'Bearer\s+([a-zA-Z0-9_\-\.]+)', r'Bearer ***'),
    (r'password[=:]\s*([^&\s]+)', r'password=***'),
    (r'secret[=:]\s*([a-zA-Z0-9_\-]+)', r'secret=***'),
    (r'hash[=:]\s*([a-f0-9]+)', r'hash=***'),
    (r'X-API-Key:\s*([a-zA-Z0-9_\-]+)', r'X-API-Key: ***'),
]

class SensitiveDataFilter(logging.Filter):
    """Filtro que reemplaza información sensible en los mensajes de log."""
    def filter(self, record):
        if hasattr(record, 'msg') and isinstance(record.msg, str):
            for pattern, replacement in SENSITIVE_PATTERNS:
                record.msg = re.sub(pattern, replacement, record.msg, flags=re.IGNORECASE)
        return True

def setup_logging():
    """Configura el logging para toda la aplicación."""
    root_logger = logging.getLogger()
    root_logger.setLevel(LOG_LEVEL)

    # Evitar duplicados si se llama varias veces
    if root_logger.handlers:
        return

    # Crear filtro de datos sensibles
    sensitive_filter = SensitiveDataFilter()

    # Handler para archivo con rotación (10 MB, 5 backups)
    file_handler = logging.handlers.RotatingFileHandler(
        LOG_DIR / "app.log",
        maxBytes=10*1024*1024,
        backupCount=5,
        encoding="utf-8"
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.addFilter(sensitive_filter)
    file_formatter = logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT)
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)

    # Handler para consola (solo niveles >= LOG_LEVEL)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.getLevelName(LOG_LEVEL))
    console_handler.addFilter(sensitive_filter)
    console_formatter = logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT)
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)

    # Handler para errores separado (opcional)
    error_handler = logging.handlers.RotatingFileHandler(
        LOG_DIR / "error.log",
        maxBytes=10*1024*1024,
        backupCount=5,
        encoding="utf-8"
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.addFilter(sensitive_filter)
    error_handler.setFormatter(file_formatter)
    root_logger.addHandler(error_handler)

    return root_logger

def get_logger(name):
    """Obtiene un logger con el nombre dado."""
    return logging.getLogger(name)