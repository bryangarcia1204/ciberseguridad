import os
import shutil
import datetime
import tarfile
from cryptography.fernet import Fernet
from pathlib import Path

try:
    import keyring
    KEYRING_AVAILABLE = True
except ImportError:
    KEYRING_AVAILABLE = False

SERVICE_NAME = "CiberseguridadBackup"
ENV_KEY = os.environ.get("BACKUP_ENCRYPTION_KEY")

import getpass

def get_encryption_key():
    """Solicita la contraseña maestra al usuario y deriva la clave."""
    # En un entorno de servidor, esto no es práctico. Mejor usar variable de entorno.
    # Para backups automáticos, se necesita una clave persistente.
    # Por tanto, mantenemos keyring como opción, pero añadimos una advertencia.
    env_key = os.environ.get("BACKUP_ENCRYPTION_KEY")
    if env_key:
        return env_key.encode()
    # Usar keyring con una nota de seguridad
    key = keyring.get_password(SERVICE_NAME, "backup_key")
    if key:
        return key.encode()
    # Si no existe, generar y guardar en keyring (con advertencia)
    import secrets
    key = secrets.token_urlsafe(32)
    keyring.set_password(SERVICE_NAME, "backup_key", key)
    print("⚠️ Clave de backup generada y almacenada en keyring. Asegúrate de que el almacén sea seguro.")
    return key.encode()

def backup_files(source_dir, backup_dir, encrypt=True):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = f"backup_{timestamp}.tar.gz"
    backup_path = os.path.join(backup_dir, backup_filename)

    with tarfile.open(backup_path, "w:gz") as tar:
        tar.add(source_dir, arcname=os.path.basename(source_dir))

    if encrypt:
        key = get_encryption_key()
        f = Fernet(key)
        with open(backup_path, "rb") as file:
            file_data = file.read()
        encrypted_data = f.encrypt(file_data)
        encrypted_path = backup_path + ".enc"
        with open(encrypted_path, "wb") as file:
            file.write(encrypted_data)
        os.remove(backup_path)
        return f"Backup cifrado guardado: {encrypted_path}"
    else:
        return f"Backup guardado: {backup_path}"