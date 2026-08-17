import os
import json
import platform
from pathlib import Path

# Lista completa de módulos continuos (incluyendo ai_analyzer y cleanup_module)
continuous_modules = [
    "honeypot",
    "log_monitor",
    "network_scanner",
    "packet_sniffer",
    "ransomware_shield",
    "waf_module",
    "integrity_checker",
    "ai_analyzer",
    "cleanup_module"
]

# Directorio de configuraciones
config_dir = Path("config")
config_dir.mkdir(parents=True, exist_ok=True)

# Directorio para datos persistentes (archivos generados)
data_dir = Path("data")
data_dir.mkdir(parents=True, exist_ok=True)

system = platform.system()

# Valores por defecto según SO
if system == 'Windows':
    default_logfile = "C:/Windows/System32/LogFiles/Firewall/pfirewall.log"
    default_integrity_dir = "C:/"
    default_ransomware_dir = "C:/Users"
    default_waf_backend = "http://localhost:80"
else:
    default_logfile = "/var/log/apache2/access.log"
    default_integrity_dir = "/etc"
    default_ransomware_dir = "/home"
    default_waf_backend = "http://localhost:80"

# Rutas relativas para archivos de datos
known_devices_file = str(data_dir / "known_devices.json")
baseline_file = str(data_dir / "baseline.json")

# Configuraciones por defecto detalladas
default_configs = {
    "honeypot": {
        "host": "0.0.0.0",
        "port": 0,  # puerto automático
        "service": "tcp",
        "banner": "Bienvenido al servidor falso",
        "log_payload": True,
        "tarpit": False
    },
    "log_monitor": {
        "logfile": default_logfile,
        "threshold": 100
    },
    "network_scanner": {
        "ip_range": "192.168.1.0/24",
        "known_devices_file": known_devices_file,
        "scan_interval": 60
    },
    "packet_sniffer": {
        "verbose": False,
        "method": "auto"
    },
    "ransomware_shield": {
        "directories": [default_ransomware_dir],
        "threshold": 100,
        "window_seconds": 60,
        "exclude_patterns": [
            "C:/Users/*/AppData/Local/Temp/*",
            "*.tmp",
            "*.log",
            "C:/Windows/Temp/*"
        ],
        "process_whitelist": ["systemd", "kernel", "svchost.exe", "TrustedInstaller.exe"],
        "scan_with_antivirus": True,
        "backend_antivirus": "auto"
    },
    "waf_module": {
        "host": "0.0.0.0",
        "port": 8080,  # puerto no privilegiado
        "default_backend": default_waf_backend,
        "backends": {},
        "backend_verify_ssl": True,
        "backend_timeout": 30,
        "allowed_backend_ips": [
            "127.0.0.1",
            "::1",
            "192.168.0.0/16",
            "10.0.0.0/8",
            "172.16.0.0/12"
        ],
        "ssl_certfile": None,
        "ssl_keyfile": None,
        "enable_sqli": True,
        "enable_xss": True,
        "enable_path_traversal": True,
        "enable_cmd_injection": False
    },
    "integrity_checker": {
        "directory": default_integrity_dir,
        "baseline_file": baseline_file,
        "interval": 3600
    },
    "ai_analyzer": {
        "enable_packet_sniffer": True,
        "packet_sniffer_config": {
            "analyzer_interval": 3600,
            "detection_interval": 300,
            "window_days": 7,
            "min_samples": 100,
            "contamination": 0.01
        },
        "enable_waf_module": True,
        "waf_module_config": {
            "analyzer_interval": 3600,
            "detection_interval": 300,
            "window_days": 7,
            "min_samples": 50,
            "contamination": 0.01
        },
        "enable_honeypot": True,
        "honeypot_config": {
            "analyzer_interval": 3600,
            "detection_interval": 300,
            "window_days": 7,
            "min_samples": 50,
            "contamination": 0.01
        },
        "enable_log_monitor": True,
        "log_monitor_config": {
            "analyzer_interval": 3600,
            "detection_interval": 300,
            "window_days": 7,
            "min_samples": 100,
            "contamination": 0.01
        },
        "enable_ransomware_shield": True,
        "ransomware_shield_config": {
            "analyzer_interval": 3600,
            "detection_interval": 300,
            "window_days": 7,
            "min_samples": 50,
            "contamination": 0.02
        },
        "enable_network_scanner": False,
        "network_scanner_config": {
            "analyzer_interval": 7200,
            "detection_interval": 600,
            "window_days": 7,
            "min_samples": 30,
            "contamination": 0.01
        },
        "enable_integrity_checker": True,
        "integrity_checker_config": {
            "analyzer_interval": 3600,
            "detection_interval": 300,
            "window_days": 7,
            "min_samples": 20,
            "contamination": 0.01
        }
    },
    "cleanup_module": {
        "retention_days": 30,
        "interval": 86400
    }
}

# Crear archivos de configuración si no existen
for module in continuous_modules:
    config_file = config_dir / f"{module}.json"
    if not config_file.exists():
        with open(config_file, "w") as f:
            json.dump(default_configs.get(module, {}), f, indent=2)
        print(f"Configuración por defecto creada para {module}")
    else:
        print(f"Configuración existente para {module}, no se sobrescribe")

if system == 'Windows':
    print("\nNOTA: En Windows, el módulo log_monitor usa el log del firewall.")
    print("      Asegúrate de activar el registro de paquetes en el firewall de Windows.")