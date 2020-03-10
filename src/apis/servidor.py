import os
from functools import wraps

from flask import request
from flask_restplus import Namespace, Resource, fields

from core.file_utils import FileUtils

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
    @token_required
    def get(self):
        return {"hola": "mundo"}
