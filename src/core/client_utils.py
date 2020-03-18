import hashlib
import hmac
import json
import os
import shutil
from datetime import datetime
from functools import reduce

from apscheduler.schedulers.background import BackgroundScheduler


class ClientUtils():
    """
    Class for client
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


