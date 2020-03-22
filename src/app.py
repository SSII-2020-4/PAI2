import os

from flask import Flask
from dotenv import load_dotenv

from apis import api


load_dotenv(".env")

# Comprobar que las variables de entornos necesias existen
strMensajeVaribleError = "ERROR , NO SE HA DEFINIDO LA VARIABLE : "


def check_enviroment():
    b_check_environment = True

    if ("TOKENS" not in os.environ):
        print(strMensajeVaribleError + "TOKENS")
        b_check_environment = False
    return b_check_environment


b_entorno = check_enviroment()

if b_entorno:
    app = Flask(__name__)
    api.init_app(app)
    if __name__ == "__main__":
        app.run(debug=True)
