from flask_restplus import Api
from .cliente import api as api_client
from .servidor import api as api_server

api = Api(
    title="PAI1",
    description="Proof of Possession",
    version="1.0",
)

api.add_namespace(api_client)
api.add_namespace(api_server)
