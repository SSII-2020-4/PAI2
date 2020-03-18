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
        digest_maker = hmac.new(key, msg=message, digestmod=algorithm)
        digest_maker.update(nonce)
        digest_maker.hexdigest()
        return digest_maker.hexdigest()


