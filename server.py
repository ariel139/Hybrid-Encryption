import socket
import threading
import time
import traceback
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Hybrid_Encryption import Encryption, Encryption_Method
from Crypto.Util.Padding import pad, unpad
from dh import dh

# Generate a 256-bit (32-byte) random key
key = get_random_bytes(16)
AES_KEY_SIZE = 24  # BYTES
running = True
threads = []

def receive(soc: socket.socket):
    data = b''
    try:
        while True:
            temp_data = soc.recv(1024)
            data += temp_data
            if temp_data[-3:] == b'###':
                break
    except socket.error as err:
        raise Exception(err)
    return data

def check_errors(data):
    fildes = data.decode().split('#')
    codes = ['SPK','SEK','SDI']
    if fildes[0] not in codes:
        return False, 'ENC'
    return  True, 'NNN'
    # more will be there


def generate_aes_key(size: int):
    if size not in [16,24,32]:
        raise Exception('invalid key size')
    return get_random_bytes(size)


def send_error(soc, code):
    soc.send(code.encode())


def key_exchange(soc : socket.socket, enc: Encryption):
    public_key_data = receive(soc)  # max 4096 key size + 3 code 1 extra
    worked, code = check_errors(public_key_data)
    public_key = public_key_data.decode().split('#')[1].encode()

    if not worked:
        send_error(soc, code)
    if enc.method ==Encryption_Method.RSA:
        aes_key = generate_aes_key(AES_KEY_SIZE)
        enc.set_public_key(public_key)
        encrypted_aes = enc.encrypt(aes_key)
        soc.send(b'SEK#' + encrypted_aes + b'###')
    else:
        aes_key = enc.decrypt(public_key)
        soc.send(b'SEK#' + enc.get_public_key() + b'###')

    return aes_key


def encrypt_data(data:bytes, key):
    cipher = AES.new(key, AES.MODE_CBC)
    cipher_text = cipher.encrypt(pad(data, AES.block_size))
    iv = cipher.iv
    return cipher_text, iv


def decrypet_data(decrypted_aes_key, data: bytes, iv):
    if isinstance(decrypted_aes_key,int):
        decrypted_aes_key = decrypted_aes_key.to_bytes(dh.bytes_needed(decrypted_aes_key),'little')
    cipher = AES.new(decrypted_aes_key, AES.MODE_CBC, iv)
    decrypt_cipher = cipher.decrypt(data)
    return unpad(decrypt_cipher, AES.block_size)


def get_iv(soc: socket.socket):
    iv_data = receive(soc)
    return iv_data[4:-3]


def remove_protocol_data(data:bytes):
    return data[4:-3]


def exchange_method(soc: socket.socket) -> Encryption_Method:
    method = receive(soc)
    method_ans = None
    ans = b'OK###'
    if method == b'RSA###':
        method_ans= Encryption_Method.RSA
    elif method == b'DPH###':
        method_ans =  Encryption_Method.DPH
    else:
        ans = 'ERR-1###'
    soc.send(ans)
    return method_ans


def handle_client(soc):
    enc_method = exchange_method(soc)
    enc_object = Encryption(enc_method)
    aes_key = key_exchange(soc, enc_object)
    iv = get_iv(soc)
    while True:
        data = receive(soc)
        if data == b'':
            break
        decrypted_data = decrypet_data(aes_key,remove_protocol_data(data),iv).decode()
        print('data is: '+decrypted_data)


def main():
    global running, threads
    try:
        server_socket = socket.socket()
        server_socket.bind(('127.0.0.1', 8200))
        server_socket.listen(4)
        while running:
            client_sock, addr = server_socket.accept()
            print('[+] New Connection from IP: '+addr[0] + ' in src port :' + str(addr[1]))
            client_thread = threading.Thread(target=handle_client, args=(client_sock,))
            threads.append(client_thread)
            client_thread.start()

    except Exception as er:
        print('error in server:')
        traceback.print_exc()

        running = False
        for t in threads:
            t.join()


if __name__ == "__main__":
    main()
