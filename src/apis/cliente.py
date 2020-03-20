import os
import requests
import json
from functools import wraps
from core.client_utils import ClientUtils

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
    'Client',
    description='Client simulation',
    # authorizations=authorizations
)

model_message = api.model(
    'Message', {
        'message': fields.String(
            required=True,
            description="Message to send (Cuenta origen, Cuenta destino, \
                Cantidad transferida)"),
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


base_url = "http://127.0.0.1:5000/"


@api.route("/")
# @api.response(401, "Not Authorized")
class Files(Resource):
    @api.doc(description="Get all files and hashes",
             security='apikey',
             responses={
                 200: "Files and hashes",
                 500: "HIDS failure. Please populate files"
             })
    @token_required
    def get(self):
        return {"hola": "mundo"}

    @api.expect(model_message)
    @api.doc(description="Manda un mensaje sobre una transacción",
             security='apikey',
             responses={
                 200: "El mensaje ha sido recibido con éxito",
                 500: "La integridad del mensaje se ha visto comprometida"
             })
    def post(self):
        client = ClientUtils()
        message = request.json["message"]

        # Intercambio de claves

        # Simulación de parámetros. Corregir cuando se implemente
        nonce = client.gen_nonce()[0]
        full_key = 123456

        MAC = client.calculate_mac(nonce, message, full_key)
        data = {
            "message": message,
            "MAC": MAC,
            "nonce": nonce
        }

        r = requests.post(
            f"{base_url}Server/",
            data=json.dumps(data),
            headers={'content-type': 'application/json'}
        )

        return r.text
