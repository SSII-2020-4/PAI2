import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime
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


class ServerUtils():
    """
    Class for server
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

    def get_transference_rate(self, is_integrity_violated: bool, message: str):
        """
        Devuelve la tasa de transferencia
        mensajes_enviados_integros / mensajes_totales.
        Además, acutaliza el archivo de logs.

        is_integrity_violated -- Boolean que determina si la integridad
        del mensaje ha sido violada
        message -- Mensaje enviado por el cliente
        """
        if not os.path.exists("files"):
            os.mkdir("files")
        file_backup = os.path.join(
            os.getcwd(),
            "files",
            ".transference_rate_backup"
        )
        file_log = os.path.join(
            os.getcwd(),
            "files",
            "logs.log"
        )
        if not os.path.exists(file_backup):
            os.mknod(file_backup)
        if not os.path.exists(file_log):
            os.mknod(file_log)
        with open(file_backup, "r") as file:
            try:
                loaded_rate = json.load(file)
            except Exception:
                loaded_rate = {"success": 0, "total": 0}

        try:
            loaded_rate["total"] = loaded_rate["total"] + 1

            if (not is_integrity_violated):
                loaded_rate["success"] = loaded_rate["success"] + 1
            else:
                with open(
                    file_log,
                    "a+",
                    encoding="utf-8"
                ) as file:

                    file.write(
                        "[" + datetime.now().strftime("%d/%m/%Y %H:%M:%S") +
                        "] - Se ha violado la integridad del mensaje: " +
                        message + "\n"
                    )

            rate = loaded_rate["success"] / loaded_rate["total"] * 100
        except ZeroDivisionError:
            rate = 0
        finally:
            with open(file_backup, "w") as file:
                file.write(json.dumps(loaded_rate))

        if (not is_integrity_violated):
            res = "Se ha mantenido la integridad del mensaje. " + \
                "Tasa de acierto en la transferencia: " + \
                str("{0:.2f}".format(rate)) + "%", 200
        else:
            res = "La integridad del mensaje se ha visto comprometido. " + \
                "Tasa de acierto en la transferencia: " + \
                str("{0:.2f}".format(rate)) + " %", 400

        return res

    def gen_nonce(self, length=32):
        """
        Generates a random string in hexadecimal with 32 random
        bytes by default
        """
        if(length < 32):
            res = {"message": 'Invalid nonce length'}, 400
        else:
            nonce = secrets.token_hex(floor(length))
            nonces_file = "server-generate-nonces.txt"
            res = self.check_nonce(nonce, nonces_file, length)
        return res

    def check_nonce(self, nonce, nonces_file="server-received-nonces.txt", length=32):
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
        full_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=None,
            backend=default_backend()
        ).derive(shared_key)
        return full_key
