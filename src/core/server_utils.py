import hashlib
import hmac
import json
import os
import shutil
from datetime import datetime
from functools import reduce

from apscheduler.schedulers.background import BackgroundScheduler


class ServerUtils():
    """
    Class for server
    """
