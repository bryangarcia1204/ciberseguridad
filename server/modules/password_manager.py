import secrets
import string
import json
import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import keyring

SERVICE_NAME = "CiberseguridadPasswordManager"

class PasswordManager:
    _instance = None

    def __new__(cls, master_password=None):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, master_password=None):
        if hasattr(self, '_initialized') and self._initialized:
            return
        self._initialized = True

        if master_password is None:
            master_password = keyring.get_password(SERVICE_NAME, "master_password")
            if master_password is None:
                raise Exception("Se requiere contraseña maestra. Use set_master_password() o defina la variable de entorno PASSWORD_MANAGER_MASTER_PASSWORD")
        self.master_password = master_password
        self.salt = self._load_salt()
        self.key = self._derive_key()
        self.cipher = Fernet(self.key)
        self.db_file = "data/passwords.enc"
        self.db = self._load_db()

    def _derive_key(self):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.master_password.encode()))
        return key

    def _load_salt(self):
        salt_file = "data/password_salt.bin"
        if os.path.exists(salt_file):
            with open(salt_file, "rb") as f:
                return f.read()
        else:
            salt = os.urandom(16)
            os.makedirs(os.path.dirname(salt_file), exist_ok=True)
            with open(salt_file, "wb") as f:
                f.write(salt)
            return salt

    def _load_db(self):
        if os.path.exists(self.db_file):
            with open(self.db_file, "rb") as f:
                encrypted = f.read()
            try:
                decrypted = self.cipher.decrypt(encrypted)
                return json.loads(decrypted.decode())
            except:
                return {}
        else:
            return {}

    def _save_db(self):
        data = json.dumps(self.db).encode()
        encrypted = self.cipher.encrypt(data)
        os.makedirs(os.path.dirname(self.db_file), exist_ok=True)
        with open(self.db_file, "wb") as f:
            f.write(encrypted)

    def export_db(self, password):
        """Exporta la base de datos cifrada con una contraseña proporcionada."""
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        cipher = Fernet(key)
        data = json.dumps(self.db).encode()
        encrypted = cipher.encrypt(data)
        return base64.b64encode(salt + encrypted).decode()

    def import_db(self, exported_data, password):
        """Importa una base de datos desde un string exportado."""
        raw = base64.b64decode(exported_data)
        salt = raw[:16]
        encrypted = raw[16:]
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        cipher = Fernet(key)
        decrypted = cipher.decrypt(encrypted)
        self.db = json.loads(decrypted.decode())
        self._save_db()

    @staticmethod
    def set_master_password(master_password):
        keyring.set_password(SERVICE_NAME, "master_password", master_password)

    @staticmethod
    def generate_password(length=16):
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    def add_password(self, service, username, password=None):
        if not password:
            password = self.generate_password()
        self.db[service] = {"username": username, "password": password}
        self._save_db()
        return password

    def get_password(self, service):
        return self.db.get(service)

    def list_services(self):
        """Devuelve una lista de servicios con usuario (sin contraseñas)."""
        return [{"service": s, "username": v["username"]} for s, v in self.db.items()]

    def delete_password(self, service):
        if service in self.db:
            del self.db[service]
            self._save_db()
            return True
        return False
    # password_manager.py (añadir al final)

def init_password_manager():
    """
    Inicializa y devuelve una instancia de PasswordManager.
    La contraseña maestra se obtiene de:
    1. Variable de entorno PASSWORD_MANAGER_MASTER_PASSWORD
    2. Keyring (si existe)
    3. Se genera una nueva y se guarda en keyring (con advertencia)
    """
    import os
    import keyring
    import secrets

    master_pw = os.environ.get("PASSWORD_MANAGER_MASTER_PASSWORD")
    if not master_pw:
        master_pw = keyring.get_password(SERVICE_NAME, "master_password")
        if not master_pw:
            master_pw = secrets.token_urlsafe(20)
            keyring.set_password(SERVICE_NAME, "master_password", master_pw)
            print("⚠️  PASSWORD_MANAGER_MASTER_PASSWORD no definida. Se ha generado una contraseña maestra temporal y guardada en keyring.")
    return PasswordManager(master_pw)