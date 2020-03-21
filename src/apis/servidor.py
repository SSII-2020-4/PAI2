import os
from functools import wraps

from flask import g, request
from flask_restplus import Namespace, Resource, fields

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
    # authorizations=authorizations
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


@api.route("/public_key")
@api.hide
# @api.response(401, "Not Authorized")
class PublicKeyTransfer(Resource):
    @api.doc(description="Clave compartida",
             security='apikey',
             responses={
                 200: "Clave compartida generada",
             })
    @api.expect(model_public_key)
    def post(self):
        public_key = edh.get_public_key()
        return public_key.decode('ascii')


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
    def post(self):
        g._messages = {}
        client_public_key = request.json['public_key']
        shared_key = edh.get_shared_key(client_public_key)
        return shared_key, 200


@api.route("/message")
@api.hide
class Message(Resource):
    @api.doc(description="Get all files and hashes",
             security='apikey',
             responses={
                 200: "Files and hashes",
                 500: "HIDS failure. Please populate files"
             })
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
        mac_calculated = server.calculate_mac(nonce, message, full_key)

        integrity_violated = str(MAC) != str(mac_calculated)

        return server.get_transference_rate(integrity_violated, message)
