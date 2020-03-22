from flask_restplus import Api
from .cliente import api as api_client
from .servidor import api as api_server

api = Api(
    title="PAI2",
    description="Simulación del canal de comunicación" +
    " entre cliente y servidor",
    version="1.0",
)

api.add_namespace(api_client)
api.add_namespace(api_server)
