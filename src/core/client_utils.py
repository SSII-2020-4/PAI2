import hashlib
import hmac
import json
import os
import secrets
from math import floor

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (Encoding,
                                                          ParameterFormat,
                                                          PublicFormat,
                                                          load_pem_parameters,
                                                          load_pem_public_key)

from .common_utils import Utils


class ClientUtils():
    """
    Class for client
    """

    def calculate_mac(
        self,
        key: bytes,
        message: bytes,
        nonce: bytes,
        algorithm=hashlib.sha256
    ):
        """
        Calcula el MAC de un mensaje y el nonce, pasando la clave como
        parámetros. Estos 3 campos deben ser en bytes.

        key -- Clave compartida entre el cliente y el servidor
        message -- Mensaje enviado por el cliente
        nonce -- Número aleatorio único entre el cliente y el servidor
        algorithm -- (Opcional) Algoritmo a usar para el cálculo del MAC
        """
        key_bytes = str.encode(str(key))
        message_bytes = str.encode(str(message))
        nonce_bytes = str.encode(str(nonce))

        digest_maker = hmac.new(
            key_bytes,
            msg=message_bytes,
            digestmod=algorithm
        )
        digest_maker.update(nonce_bytes)
        digest_maker.hexdigest()
        return digest_maker.hexdigest()

    def gen_nonce(self, length=32):
        """
        Generates a random string in hexadecimal with 32 random
        bytes by default
        """
        if(length < 32):
            res = {"message": 'Invalid nonce length'}, 400
        else:
            nonce = secrets.token_hex(floor(length))
            nonces_file = "client-generate-nonces.txt"
            res = self.check_nonce(length, nonce, nonces_file)
        return res

    def check_nonce(self, length, nonce, nonces_file):
        res = {"nonce": nonce}, 200
        if not os.path.exists(nonces_file):
            os.mknod(nonces_file)
        with open(nonces_file, 'r') as f:
            linea = f.readline()
            aux = True
            while linea != "":
                if(linea.strip() == nonce):
                    aux = False
                    break
                linea = f.readline()
            if(aux):
                f = open(nonces_file, "a")
                f.write(nonce + "\n")
            else:
                res = {"message": 'Used nonce'}, 401
        return res


class EDH():
    def __init__(self):
        self.__generate_parameters()

    def __generate_parameters(self):
        param_file = 'dh.pem'
        if not os.path.isfile(param_file):
            self.__parameters = dh.generate_parameters(
                generator=2,
                key_size=2048,
                backend=default_backend()
            )
            dh_pem = self.__parameters.parameter_bytes(
                Encoding.PEM,
                ParameterFormat.PKCS3
            )
            with open(param_file, 'wb') as output:
                output.write(dh_pem)
        else:
            with open(param_file, 'rb') as binary_file:
                pem_data = binary_file.read()
                self.__parameters = load_pem_parameters(
                    pem_data,
                    default_backend()
                )
        self.__private_key = self.__parameters.generate_private_key()
        self.__full_key = None

    def get_public_key(self):
        public_key = self.__private_key.public_key()
        public_key = public_key.public_bytes(
            Encoding.PEM,
            PublicFormat.SubjectPublicKeyInfo
        )
        return public_key

    def get_shared_key(self, server_public_key):
        server_public_key = load_pem_public_key(
            str.encode(
                server_public_key.replace('\"', "").replace("\\n", "\n")
            ),
            default_backend()
        )
        self.shared_key = self.__private_key.exchange(
            server_public_key
        ).hex()
        return self.shared_key

    def get_full_key(self, shared_key):
        shared_key = str.encode(
            shared_key.replace("\"", "").replace("\n", "")
        )
        self.__full_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=None,
            backend=default_backend()
        ).derive(shared_key)
        return self.__full_key

    def exchange_keys(self, token):
        utils = Utils()
        if self.__full_key is not None:
            res = self.__full_key
        else:
            # Intercambio de claves
            #################
            # Clave pública #
            #################
            server_public_key = json.loads(utils.api_request(
                "get",
                "server/public_key",
                token=token
            )[0])['public_key']

            ####################
            # Clave compartida #
            ####################
            client_shared_key = self.get_shared_key(server_public_key)
            data = {
                "public_key": self.get_public_key().decode('ascii'),
                "shared_key": client_shared_key,
            }
            server_shared_key = json.loads(utils.api_request(
                "post",
                "server/shared_key",
                data=data,
                token=token,
            )[0])["shared_key"]

            ##################
            # Clave completa #
            ##################
            res = self.get_full_key(server_shared_key)

        return res
