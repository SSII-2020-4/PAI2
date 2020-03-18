import hashlib
import hmac
import json
import os
import secrets
import shutil
import datetime
from datetime import datetime
from functools import reduce
from math import floor


class ServerUtils():
    """
    Class for server
    """

    def calculate_MAC(key : bytes, message : bytes, nonce : bytes, algorithm=hashlib.sha256):
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

    def get_transference_rate(is_integrity_violated : bool, message : str):
        """
        Devuelve la tasa de transferencia mensajes_enviados_integros / mensajes_totales. Además, acutaliza el archivo de logs.

        is_integrity_violated -- Boolean que determina si el mensaje la integridad ha sido violada
        message -- Mensaje enviado por el cliente
        """

        with open(os.path.join(os.getcwd(), "files", ".transference_rate_backup"), "r") as file:
            loaded_rate = json.load(file)

        try:
            loaded_rate["total"] = loaded_rate["total"] + 1
            
            if (is_integrity_violated):
                loaded_rate["success"] = loaded_rate["success"] + 1            
            else:
                with open(os.path.join(os.getcwd(), "files", "logs.log"), "a+", encoding="utf-8") as file:
                    file.write("[" + datetime.now().strftime("%d/%m/%Y %H:%M:%S") + "] - Se ha violado la integridad del mensaje: " + message "\n")

            rate = loaded_rate["success"] / loaded_rate["total"] * 100
        except ZeroDivisionError as e:
            rate = 0
        finally:
            with open(os.path.join(os.getcwd(), "files", ".transference_rate_backup"), "w") as file:
                file.write(json.dumps(loaded_rate))

        return rate

    
    def gen_nonce(self, length=32):
        """ Generates a random string in hexadecimal with 32 random bytes by default """
        if(length<32):
            res= 'Invalid nonce length', 400
        else:
            res= secrets.token_hex(floor(length)), 200
        return res