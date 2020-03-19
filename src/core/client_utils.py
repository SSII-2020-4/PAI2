import base64
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

    def calculate_MAC(self,key : bytes, message : bytes, nonce : bytes, algorithm=hashlib.sha256):
        """
        Calcula el MAC de un mensaje y el nonce, pasando la clave como parámetros. Estos 3 campos deben ser en bytes.

        key -- Clave compartida entre el cliente y el servidor
        message -- Mensaje enviado por el cliente
        nonce -- Número aleatorio único entre el cliente y el servidor 
        algorithm -- (Opcional) Algoritmo a usar para el cálculo del MAC
        """
        digest_maker = hmac.new(key, msg=message, digestmod=algorithm)
        digest_maker.update(nonce)
        digest_maker.hexdigest()
        return digest_maker.hexdigest()

    def gen_nonce(self, length=32):
        """ Generates a random string in hexadecimal with 32 random bytes by default """
        if(length<1):
            res= {"message":'Invalid nonce length'}, 400
        else:
            res= {"nonce":secrets.token_hex(floor(length))}, 200
            if(not os.path.isfile("client-nonces.txt")):
                f = open("client-nonces.txt","w")
            f = open("client-nonces.txt","r")
            linea = f.readline()
            aux = True
            while linea != "":
                if(linea == res[0]["nonce"]+"\n"):
                    aux = False
                    break
                linea = f.readline()
            if(aux):
                f = open("client-nonces.txt","a")
                f.write(res[0]["nonce"]+"\n")
            else:
                res = {"message":'Used nonce'}, 401
        return res
