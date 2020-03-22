import json
import os
from functools import wraps

from flask import request
from flask_restplus import Namespace, Resource, fields

from core.client_utils import EDH, ClientUtils
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
    authorizations=authorizations
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

message_from_server = api.model(
    'Data', {
        'message': fields.String(
            required=True,
            description="Message from server"),
        'MAC': fields.String(
            required=True,
            description="Message Authentication Code from server"),
        'nonce': fields.Integer(
            required=True,
            description="Random number used once"),
    }
)

model_message = api.model(
    'clientMessage', {
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
@api.response(401, "Not Authorized")
class PublicKeyTransfer(Resource):
    @api.doc(description="Clave pública",
             security='apikey',
             responses={
                 200: "Clave pública generada",
             })
    @token_required
    def get(self):
        public_key = edh.get_public_key()
        return {"public_key": public_key.decode('ascii')}


@api.route('/send_message')
class Message(Resource):
    @api.doc(description="Manda un mensaje sobre una transacción",
             security='apikey',
             responses={
                 200: "El mensaje ha sido recibido con éxito",
                 405: "Método no permitido",
                 400: "La integridad del mensaje se ha visto comprometida"
             })
    @token_required
    @api.expect(model_message)
    def post(self):
        client = ClientUtils()
        message = str(request.json)

        # Intercambio de claves
        if request.headers['X-API-KEY']:
            token = request.headers['X-API-KEY']
        full_key = edh.exchange_keys(token)
        # full_key = 1234

        # Simulación de parámetros.
        nonce = client.gen_nonce()[0]['nonce']
        MAC = client.calculate_mac(full_key, message, nonce)
        data = {
            "message": message,
            "MAC": MAC,
            "nonce": nonce,
            "shared_key": edh.shared_key
        }

        response = utils.api_request(
            "post",
            "server/receive_message",
            data=data,
            token=token
        )

        return json.loads(response[0]), response[1]


@api.route("/receive_message")
@api.hide
class Message(Resource):
    @api.doc(description="Recibe un mensaje sobre una transacción",
             security='apikey',
             responses={
                 200: "El mensaje ha sido recibido con éxito",
                 405: "Método no permitido",
                 400: "La integridad del mensaje se ha visto comprometida"
             })
    @api.expect(message_from_server)
    @token_required
    def post(self):
        client = ClientUtils()
        message = request.json["message"]
        # Intercambio de claves
        full_key = edh.get_full_key(request.json["shared_key"])
        # full_key = 1234

        # Simulación de parámetros.
        nonce = request.json["nonce"]
        MAC = request.json["MAC"]

        mac_calculated = client.calculate_mac(full_key, message, nonce)
        integrity_violated = str(MAC) != str(mac_calculated)
        if not integrity_violated:
            res = {"message": message}, 200
        else:
            res = {"message": "Integrity violation from server to me"}, 400
        return res
