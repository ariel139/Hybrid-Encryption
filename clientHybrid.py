import socket, os, sys
import traceback

from Hybrid_Encryption import Encryption, Encryption_Method
from log import Log,log_type
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from dh import dh
Logger = Log('./log/client.log')


def receive(soc: socket.socket):
    data = b''
    try:
        while True:
            temp_data = soc.recv(1024)
            data += temp_data
            if temp_data[-3:] == b'###':
                break
    except socket.error as err:
        print( 'Error in recv :' +str(err))
    return data


def get_public_key_msg(enc_obj: Encryption):
    public_key = enc_obj.get_public_key()
    return b'SPK' + b'#' + public_key + b'###'


def exchange_keys(enc_obj: Encryption, soc: socket.socket):
    public_key_msg = get_public_key_msg(enc_obj)
    soc.send(public_key_msg)
    aes_key = receive(soc)
    if aes_key[:4] == b'SEK#' and aes_key[-3:] == b'###':
        aes_key =  aes_key[4:-3]

    if enc_obj.method == Encryption_Method.RSA:
        aes_key = enc_obj.decrypt(aes_key)
    else:
        aes_key = enc_obj.decrypt(aes_key)
    Logger.log(aes_key,log_type.ENCRYPTED_DATA)
    return aes_key


def encrypt_data(data:bytes, key:[bytes,int], iv):
    if isinstance(key,int):
        key = int.to_bytes(key, dh.bytes_needed(key),'little')
    cipher = AES.new(key, AES.MODE_CBC,iv)

    cipher_text = cipher.encrypt(pad(data, AES.block_size))
    return cipher_text


def decrypet_data(decrypted_aes_key, data: bytes, iv):
    cipher = AES.new(decrypted_aes_key, AES.MODE_CBC, iv)
    decrypt_cipher = cipher.decrypt(data)
    return unpad(decrypt_cipher, AES.block_size)


def exchange_method(method: Encryption_Method, soc: socket.socket):
    if method == Encryption_Method.RSA:
        data = b'RSA###'
    elif method == Encryption_Method.DPH:
        data = b'DPH###'
    else:
        raise Exception('UnKnown Method')
    soc.send(data)
    ack = receive(soc)
    if ack != b'OK###':
        raise Exception('Problem in server while choosing methods!')


def main(ip:str, port:int, method: Encryption_Method, data:bytes):
    try:
        sock = socket.socket()
        sock.connect((ip, port))

        # create iv:
        if method == Encryption_Method.RSA:
            exchange_method(Encryption_Method.RSA, sock)
        else:
            exchange_method(Encryption_Method.DPH, sock)

        # create public and private  keys
        enc_data = Encryption(method)

        decrypted_key = exchange_keys(enc_data, sock)
        Logger.log(decrypted_key,log_type.DECRYPTED_DATA)
        iv = os.urandom(16)
        sock.send(b'SIV#'+iv+b'###')
        if method == Encryption_Method.RSA:
            encrypted_data = encrypt_data(data, decrypted_key, iv)
        elif method.DPH:
            encrypted_data = encrypt_data(data, decrypted_key.to_bytes(16,'little'), iv)
        sock.send(b'SDI#'+encrypted_data+b'###')
        sock.close()
    except Exception as err:
        Logger.log(err, log_type.ERRORS)
        traceback.print_exc()



