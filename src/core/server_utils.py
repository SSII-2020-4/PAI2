import hashlib
import hmac
import json
import os
import secrets
import shutil
from datetime import datetime
from functools import reduce
from math import floor


class ServerUtils():
    """
    Class for server
    """

    def calculate_MAC(self, key : bytes, message : bytes, nonce : bytes, algorithm=hashlib.sha256):
        digest_maker = hmac.new(key, msg=message, digestmod=algorithm)
        digest_maker.update(nonce)
        digest_maker.hexdigest()
        return digest_maker.hexdigest()
    
    def gen_nonce(self, length=32):
        """ Generates a random string in hexadecimal with 32 random bytes by default """
        if(length<32):
            res= 'Invalid nonce length', 400
        else:
            res= secrets.token_hex(floor(length)), 200
        return res