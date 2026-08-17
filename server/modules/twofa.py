import pyotp
import qrcode

def generate_secret():
    return pyotp.random_base32()

def get_provisioning_uri(secret, user_email, issuer='MiSistema'):
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(user_email, issuer_name=issuer)

def generate_qr(uri, filename='qrcode.png'):
    img = qrcode.make(uri)
    img.save(filename)
    return filename

def verify_code(secret, code):
    totp = pyotp.TOTP(secret)
    return totp.verify(code)