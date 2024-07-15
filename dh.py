import base64
import random
import sys


class dh:

    def __init__(self):
        self._private_key = None
        self._public_key = None
        self._p = None
        self._g = None

    def set_dh_numbers(self, p: int, g: int):
        self._p = p
        self._g = g

    def _generate_private_key(self):
        num = random.randint(0, (1 << 128) - 1)
        while num >= self._p:
            num = random.randint(0, (1 << 128) - 1)
        self._private_key =  num

    def generate_keys(self):

        self._generate_private_key()
        self._public_key = self._modular_pow(self._g,self._private_key,self._p)

    def exchange(self, key: bytes) -> int:
        if key.find(b'-----BEGIN PUBLIC KEY-----\n') == 0:
            key = self.import_key(key)
        return self._modular_pow(int.from_bytes(key, 'little'),self._private_key,self._p)
        # return int.from_bytes(key, 'little')**self._private_key % self._p

    def export_public_key(self):
        l = int.to_bytes(self._public_key,self.bytes_needed(self._public_key),'little')
        base64_value = base64.b64encode(l)
        return b'-----BEGIN PUBLIC KEY-----\n' + base64_value + b'\n-----END PUBLIC KEY-----\n'

    def export_private_key(self):
        base64_value = base64.b64encode(self._private_key)
        return b'-----BEGIN PRIVATE KEY-----\n' + base64_value + b'\n-----END PRIVATE KEY-----\n'

    def get_public_key(self):
        return self.export_public_key()

    @staticmethod
    def bytes_needed(num):
        if isinstance(num, int):
            size = sys.getsizeof(num)
            tell = num.to_bytes(size,'little')
            while tell[-1] == 0:
                tell = tell[:-1]
                size -= 1
            return size
        raise Exception('needed int type')

    @staticmethod
    def _modular_pow(base, exponent, modulus):
        result = 1
        base = base % modulus
        while exponent > 0:
            if exponent % 2 == 1:
                result = (result * base) % modulus
            exponent = exponent >> 1
            base = (base * base) % modulus
        return result

    def import_key(self,data: bytes):
        first_seq = b'-----BEGIN PUBLIC KEY-----\n'
        sec_seq = b'\n-----END PUBLIC KEY-----\n'
        first_index = data.find(first_seq)
        sec_index = data.find(sec_seq)
        if first_index ==-1 or sec_index == -1:
            raise Exception('none valid key data. expect PEM')
        data1 = data[first_index+len(first_seq):]
        data2 = data1[:sec_index-len(sec_seq)-1]

        return base64.b64decode(data2)




