from charm.toolbox.pairinggroup import extract_key
from Cryptodome.Cipher import AES
from hashlib import blake2b, sha256

class AES_EAX():

    def __init__(self, session, debug=False):
        global skey
        session_key = extract_key(session)
        skey = blake2b(session_key, digest_size=32).digest()

    def encrypt(self, data):
        cipher = AES.new(skey, AES.MODE_EAX)
        cipheredData, tag = cipher.encrypt_and_digest(data)
        return cipher.nonce, cipheredData, tag

    def decrypt(self, nonce, cipheredData, tag):
        cipher = AES.new(skey, AES.MODE_EAX, nonce)
        data = cipher.decrypt_and_verify(cipheredData, tag)
        return data
