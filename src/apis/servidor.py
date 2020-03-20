import os
from functools import wraps
from core import server_utils

from flask import request
from flask_restplus import Namespace, Resource, fields


authorizations = {
    'apikey': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'X-API-KEY',
    }
}

api = Namespace(
    'Server',
    description='Server simulation',
    # authorizations=authorizations
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
    })


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


@api.route("/")
# @api.response(401, "Not Authorized")
class Files(Resource):
    @api.doc(description="Get all files and hashes",
             security='apikey',
             responses={
                 200: "Files and hashes",
                 500: "HIDS failure. Please populate files"
             })
    @api.expect(model_message_from_client)
    def post(self):
        utils = server_utils.ServerUtils()
        message = request.json["message"]

        # Simulación de parámetros. Corregir cuando se implemente
        nonce = request.json["nonce"]
        private_key = 123456

        MAC = request.json["MAC"]
        mac_calculated = utils.calculate_mac(nonce, message, private_key)

        integrity_violated = str(MAC) != str(mac_calculated)

        return utils.get_transference_rate(integrity_violated, message)
