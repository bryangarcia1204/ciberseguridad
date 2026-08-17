# certs.py (completo, con las modificaciones)
import os
import datetime
import secrets
import string
from io import BytesIO

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import NameOID

import pyzipper  # pip install pyzipper

CERT_DIR = "data/certs"
ZIP_PATH = os.path.join(CERT_DIR, "certs.zip")
ZIP_PASSWORD_SERVICE = "zip_password"  # Nombre del servicio en el gestor

def generate_password(length=20):
    """Genera una contraseña aleatoria para el zip."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def generate_ca():
    """Genera un par de clave privada y certificado autofirmado para la CA."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Madrid"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Madrid"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MiSistema CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"MiSistema Root CA"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )
    return private_key, cert

def generate_server_cert(ca_private_key, ca_cert, common_name="CA-Raiz-Sistema-Seguridad"):
    """Genera un certificado para el servidor firmado por la CA."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"CU"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"La Habana"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Playa"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Florat Studio"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]),
            critical=False,
        )
        .sign(ca_private_key, hashes.SHA256())
    )
    return private_key, cert

def create_initial_zip(pm):
    """
    Genera la CA y el certificado del servidor, los guarda en un zip cifrado
    y almacena la contraseña en el gestor de contraseñas.
    """
    os.makedirs(CERT_DIR, exist_ok=True)

    # Generar CA y certificado del servidor
    ca_key, ca_cert = generate_ca()
    server_key, server_cert = generate_server_cert(ca_key, ca_cert, common_name="CA-Raiz-Sistema-Seguridad")

    # Convertir a PEM (bytes)
    ca_key_pem = ca_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    server_key_pem = server_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    server_cert_pem = server_cert.public_bytes(serialization.Encoding.PEM)

    # Crear zip cifrado en memoria
    zip_buffer = BytesIO()
    password = generate_password()
    with pyzipper.AESZipFile(zip_buffer, 'w', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(password.encode())
        zf.writestr("ca.key", ca_key_pem)
        zf.writestr("ca.crt", ca_cert_pem)
        zf.writestr("server.key", server_key_pem)
        zf.writestr("server.crt", server_cert_pem)

    # Guardar zip en disco
    with open(ZIP_PATH, 'wb') as f:
        f.write(zip_buffer.getvalue())

    # Guardar contraseña en el gestor de contraseñas
    pm.add_password(ZIP_PASSWORD_SERVICE, "server", password)
    return password

def load_certs_from_zip(pm):
    """
    Abre el zip cifrado usando la contraseña obtenida del gestor de contraseñas.
    """
    if not os.path.exists(ZIP_PATH):
        raise FileNotFoundError("El archivo de certificados no existe. Ejecute primero la generación inicial.")

    entry = pm.get_password(ZIP_PASSWORD_SERVICE)
    if not entry:
        raise ValueError("No se encontró la contraseña del zip en el gestor de contraseñas.")
    password = entry["password"]

    with pyzipper.AESZipFile(ZIP_PATH, 'r') as zf:
        zf.setpassword(password.encode())
        ca_key_pem = zf.read("ca.key")
        ca_cert_pem = zf.read("ca.crt")
        server_key_pem = zf.read("server.key")
        server_cert_pem = zf.read("server.crt")

    ca_key = load_pem_private_key(ca_key_pem, password=None)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    server_key = load_pem_private_key(server_key_pem, password=None)
    server_cert = x509.load_pem_x509_certificate(server_cert_pem)

    return {
        'ca_key': ca_key,
        'ca_cert': ca_cert,
        'server_key': server_key,
        'server_cert': server_cert
    }

def create_ssl_context(certs):
    """
    Crea archivos temporales para certificado, clave y CA, y devuelve un diccionario con sus rutas.
    """
    import tempfile

    cert_file = tempfile.NamedTemporaryFile(mode='wb', delete=False)
    cert_file.write(certs['server_cert'].public_bytes(serialization.Encoding.PEM))
    cert_path = cert_file.name
    cert_file.close()

    key_file = tempfile.NamedTemporaryFile(mode='wb', delete=False)
    key_file.write(certs['server_key'].private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))
    key_path = key_file.name
    key_file.close()

    ca_file = tempfile.NamedTemporaryFile(mode='wb', delete=False)
    ca_file.write(certs['ca_cert'].public_bytes(serialization.Encoding.PEM))
    ca_path = ca_file.name
    ca_file.close()

    return {
        'ssl_keyfile': key_path,
        'ssl_certfile': cert_path,
        'ssl_ca_certs': ca_path
    }