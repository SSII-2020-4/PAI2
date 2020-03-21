import json
import os
from functools import wraps

from flask import request
from flask_restplus import Namespace, Resource, fields

from core.client_utils import ClientUtils, EDH
from core.common_utils import Utils

authorizations = {
    'apikey': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'X-API-KEY',
    }
}

api = Namespace(
    'client',
    description='Simulación del cliente',
    # authorizations=authorizations
)

model_public_key = api.model(
    'Public Key', {
        'public_key': fields.String(
            required=True,
            description="Clave pública del servidor"),
    }
)

model_shared_key = api.model(
    'Shared Key', {
        'shared_key': fields.String(
            required=True,
            description="Clave compartida del servidor"),
    }
)

model_message = api.model(
    'Message', {
        'cuenta_origen': fields.String(
            required=True,
            description="Cuenta origen"),
        'cuenta_destino': fields.String(
            required=True,
            description="Cuenta destino"),
        'cantidad': fields.Integer(
            required=True,
            description="Cantidad a transferir"),
    }
)


# TOKEN check
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'X-API-KEY' in request.headers:
            token = request.headers['X-API-KEY']

        if not token:
            return {'message': 'Token is missing.'}, 401

        tokens = []
        for t in os.environ["TOKENS"].split(","):
            tokens.append(t)
        if token not in tokens:
            return {'message': 'Not Authorized.'}, 401

        return f(*args, **kwargs)
    return decorated


utils = Utils()
edh = EDH()


@api.route("/public_key")
@api.hide
# @api.response(401, "Not Authorized")
class PublicKeyTransfer(Resource):
    @api.doc(description="Clave pública",
             security='apikey',
             responses={
                 200: "Clave pública generada",
             })
    @api.expect(model_public_key)
    def post(self):
        public_key = edh.get_public_key()
        return public_key.decode('ascii')


@api.route('/message')
class Message(Resource):
    @api.expect(model_message)
    @api.doc(description="Manda un mensaje sobre una transacción",
             security='apikey',
             responses={
                 200: "El mensaje ha sido recibido con éxito",
                 405: "Método no permitido",
                 500: "La integridad del mensaje se ha visto comprometida"
             })
    def post(self):
        client = ClientUtils()
        message = str(request.json)

        # Intercambio de
        full_key = edh.exchange_keys()

        # Simulación de parámetros.
        nonce = client.gen_nonce()[0]

        MAC = client.calculate_mac(nonce, message, full_key)
        data = {
            "message": message,
            "MAC": MAC,
            "nonce": nonce,
            "shared_key": edh.shared_key
        }

        response = utils.api_request(
            "post",
            "server/message",
            data=data
        )

        return response
