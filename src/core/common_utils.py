import binascii
import os
import threading
from uuid import uuid4 as uuid

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (Encoding,
                                                          ParameterFormat,
                                                          load_pem_parameters)


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

    def __get_private_key(self):
        msg = ""
        try:
            msg = self.__private_key
        except Exception as e:
            msg += {"message": e.getMessage()}
        return msg

    def get_public_key(self):
        return self.__private_key.public_key()

    def get_shared_key(self, public_key):
        return self.__private_key.exchange(public_key)

    def __get_full_key(self, shared_key):
        full_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=None,
            backend=default_backend()
        ).derive(shared_key)
        return full_key
