from enum import Enum
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from dh import dh

DEBUG =True

DPH_VALUES =  188820646289024943196740280087076087567,76526550457502878897718726024790070449

class Encryption_Method(Enum):
    DPH = 1,
    RSA = 2

class Encryption:
    def __init__(self, method: Encryption_Method, ):
        self.method = method
        keys = self.generate_keys(self.method)
        self._private_key = keys  # might be other then 0
        if self.method == Encryption_Method.RSA:
            self._public_key = keys.public_key()  # might be other then 1
        elif self.method == Encryption_Method.DPH:
            self._public_key = keys.get_public_key()  # might be other then 1

    def generate_keys(self, method: Encryption_Method):
        if method == Encryption_Method.RSA:
            return self._generate_rsa()
        elif method == Encryption_Method.DPH:
            keys = dh()
            keys.set_dh_numbers(DPH_VALUES[0], DPH_VALUES[1])
            keys.generate_keys()
            return keys

    def _load_static_keys(self):
        with open('public_key.pem', 'rb') as f:
            public_key_bytes = f.read()
        self._public_key = serialization.load_pem_public_key(public_key_bytes)
        with open('private_key.pem', 'rb') as f:
            private_key_bytes = f.read()
        self._private_key = serialization.load_pem_private_key(
            private_key_bytes,
            password=None
        )

    def encrypt(self, data):
        if self.method == Encryption_Method.RSA:
            return self._rsa_encrypt(data)
        elif self.method == Encryption_Method.DPH:
            return self._public_key

    def decrypt(self, cipher):
        if self.method == Encryption_Method.RSA:
            return self._rsa_decrypt(cipher)
        elif self.method == Encryption_Method.DPH:
            return self._private_key.exchange(cipher)

    def set_public_key(self, public_key: bytes):
        if self.method == Encryption_Method.RSA:
            self._public_key = RSA.importKey(public_key)
        elif self.method == Encryption_Method.DPH:
            self._public_key = self._private_key.import_key(public_key)

    @staticmethod
    def _generate_rsa() -> RSA.RsaKey:
        key = RSA.generate(2048)
        return key

    def get_public_key(self):
        if self.method == Encryption_Method.RSA:
            key = self._public_key.exportKey()
        else:
            key = self._private_key.get_public_key()
        return key

    def _rsa_encrypt(self, message: bytearray):
        cipher_rsa = PKCS1_OAEP.new(self._public_key)
        return cipher_rsa.encrypt(message)

    def _rsa_decrypt(self,cipher):
        cipher_rsa = PKCS1_OAEP.new(self._private_key)
        plain_text = cipher_rsa.decrypt(cipher)
        return plain_text


    def export_keys_to_files(self, path: str, export: tuple):
        """
        exports the keys to files by the given path
        :param path: the path for the export
        :param export: gets a tuple with bool values the spot represents if you want the key exported
        first position = public key if set True will be exported
        second position = private key if set True will be exported
        :return: None - files in directory
        """
        with open(path, 'wb') as file:
            if export[0]:
                data = self._public_key.exportKey('PEM') if self.method == RSA else self._private_key.export_public_key()
                file.write(data)
            if export[1]:
                data = self._private_key.exportKey('PEM') if self.method == RSA else self._private_key.export_private_key()
                file.write(data)
