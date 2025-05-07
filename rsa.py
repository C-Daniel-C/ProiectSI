import random
from math import gcd
import json


def is_prime(n, k=5):
    if n in (2, 3):
        return True
    if n < 2 or n % 2 == 0:
        return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_large_prime(bits=512):
    while True:
        p = random.getrandbits(bits)
        p |= (1 << bits - 1) | 1
        if is_prime(p):
            return p

def extended_gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('No modular inverse')
    return x % m

def generate_keys(bits=512):
    p = generate_large_prime(bits)
    q = generate_large_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    if gcd(e, phi) != 1:
        e = 3
        while gcd(e, phi) != 1:
            e += 2
    d = modinv(e, phi)
    return (e, n), (d, n)

def encrypt_int(m, public_key):
    e, n = public_key
    return pow(m, e, n)

def decrypt_int(c, private_key):
    d, n = private_key
    return pow(c, d, n)

def string_to_int(s):
    return int.from_bytes(s.encode('utf-8'), byteorder='big')

def int_to_string(i):
    length = (i.bit_length() + 7) // 8
    return i.to_bytes(length, byteorder='big').decode('utf-8')

def encrypt_string(message, public_key):
    m_int = string_to_int(message)
    n = public_key[1]
    if m_int >= n:
        raise ValueError("Message too large for key size! Use chunking or bigger keys.")
    c_int = encrypt_int(m_int, public_key)
    return c_int

def decrypt_string(cipher_int, private_key):
    m_int = decrypt_int(cipher_int, private_key)
    return int_to_string(m_int)

def json_key(public_key):
    return json.dumps({"e": public_key[0], "n": public_key[1]})
def format_json_key_to_tuple(data):
    public_key_data = json.loads(data.decode('utf-8'))
    return (public_key_data['e'], public_key_data['n'])

public_key, private_key = generate_keys(bits=512)

# message = "Hello, world!"
# print("Original message:", message)
#
# cipher_int = encrypt_string(message, public_key)
# print("Encrypted integer:", cipher_int)
#
# decrypted_message = decrypt_string(cipher_int, private_key)
# print("Decrypted message:", decrypted_message)
# print(json_key(public_key))

# assert message == decrypted_message
