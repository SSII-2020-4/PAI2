import json
import os
from functools import wraps

from flask import request
from flask_restplus import Namespace, Resource, fields

from core.common_utils import Utils
from core.server_utils import EDH, ServerUtils

authorizations = {
    'apikey': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'X-API-KEY',
    }
}

api = Namespace(
    'server',
    description='Simulación del servidor',
    authorizations=authorizations
)

model_public_key = api.model(
    'Public Key', {
        'public_key': fields.String(
            required=True,
            description="Clave pública del cliente"),
    }
)

model_shared_key = api.model(
    'Shared Key', {
        'shared_key': fields.String(
            required=True,
            description="Clave compartida del cliente"),
    }
)

message = api.model(
    'Message', {
        'message': fields.String(
            required=True,
            description="Estado de la integridad"),
        'MAC': fields.String(
            required=True,
            description="Message Authentication Code from the server"),
        'nonce': fields.Integer(
            required=True,
            description="Random number used once"),
    }
)

model_message_from_client = api.model(
    'Data', {
        'message': fields.String(
            required=True,
            description="Message from the client"),
        'MAC': fields.String(
            required=True,
            description="Message Authentication Code from the client"),
        'nonce': fields.Integer(
            required=True,
            description="Random number used once"),
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


server = ServerUtils()
edh = EDH()
utils = Utils()


@api.route("/public_key")
@api.hide
# @api.response(401, "Not Authorized")
class PublicKeyTransfer(Resource):
    @api.doc(description="Clave compartida",
             security='apikey',
             responses={
                 200: "Clave compartida generada",
             })
    @token_required
    def get(self):
        public_key = edh.get_public_key()
        return {"public_key": public_key.decode('ascii')}


@api.route("/shared_key")
@api.hide
# @api.response(401, "Not Authorized")
class SharedKeyTransfer(Resource):
    @api.doc(description="Clave pública",
             security='apikey',
             responses={
                 200: "Clave compartida generada",
             })
    @api.expect(model_public_key)
    @token_required
    def post(self):
        client_public_key = request.json['public_key']
        shared_key = edh.get_shared_key(client_public_key)
        return {"shared_key": shared_key}, 200


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
    @token_required
    @api.expect(model_message_from_client)
    def post(self):
        server = ServerUtils()
        message = request.json["message"]

        # Intercambio de claves
        full_key = edh.get_full_key(request.json["shared_key"])
        # full_key = 1234

        # Simulación de parámetros.
        nonce = request.json["nonce"]
        MAC = request.json["MAC"]
        unique_nonce = server.check_nonce(nonce)

        mac_calculated = server.calculate_mac(full_key, message, nonce)

        integrity_violated = str(MAC) != str(mac_calculated)

        if(unique_nonce[1] != 200):
            integrity_violated = True
        # Envia mensaje de confirmación al cliente
        message = server.get_transference_rate(integrity_violated, message)
        message = message[0]

        if(unique_nonce[1] != 200):
            message += "\nNot unique nonce. Possible replay attack in server."
        nonce = server.gen_nonce()[0]['nonce']
        MAC = server.calculate_mac(full_key, message, nonce)
        data = {
            "message": message,
            "MAC": MAC,
            "nonce": nonce,
            "shared_key": edh.shared_key
        }

        if request.headers['X-API-KEY']:
            token = request.headers['X-API-KEY']
        response = utils.api_request(
            "post",
            "client/receive_message",
            data=data,
            token=token
        )

        return json.loads(response[0]), response[1]
