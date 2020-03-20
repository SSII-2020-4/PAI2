import hashlib
import hmac
import json
import os
import secrets
import shutil
from datetime import datetime
from functools import reduce
from math import floor


class ClientUtils():
    """
    Class for client
    """

    def calculate_mac(self, key: bytes, message: bytes, nonce: bytes, algorithm=hashlib.sha256):
        """
        Calcula el MAC de un mensaje y el nonce, pasando la clave como parámetros. Estos 3 campos deben ser en bytes.

        key -- Clave compartida entre el cliente y el servidor
        message -- Mensaje enviado por el cliente
        nonce -- Número aleatorio único entre el cliente y el servidor 
        algorithm -- (Opcional) Algoritmo a usar para el cálculo del MAC
        """
        key_bytes = str.encode(str(key))
        message_bytes = str.encode(str(message))
        nonce_bytes = str.encode(str(nonce))

        digest_maker = hmac.new(
            key_bytes, msg=message_bytes, digestmod=algorithm)
        digest_maker.update(nonce_bytes)
        digest_maker.hexdigest()
        return digest_maker.hexdigest()

    def gen_nonce(self, length=32):
        """ Generates a random string in hexadecimal with 32 random bytes by default """
        if(length < 1):
            res = {"message": 'Invalid nonce length'}, 400
        else:
            res = {"nonce": secrets.token_hex(floor(length))}, 200
            nonces_file = "client-nonces.txt"
            if(not os.path.isfile(nonces_file)):
                f = open(nonces_file, "w")
            f = open(nonces_file, "r")
            linea = f.readline()
            aux = True
            while linea != "":
                if(linea == res[0]["nonce"]+"\n"):
                    aux = False
                    break
                linea = f.readline()
            if(aux):
                f = open(nonces_file, "a")
                f.write(res[0]["nonce"]+"\n")
            else:
                res = {"message": 'Used nonce'}, 401
        return res
