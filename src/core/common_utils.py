import json

import requests


class Utils():

    def __init__(self):
        self.base_url = "http://127.0.0.1:5000/"

    def api_request(
        self,
        method,
        path,
        params="",
        data="",
        token="",
        header={'content-type': 'application/json'}
    ):
        """
        Calls between client and server.

        Arguments:
            method {str} -- HTTP verbs
            path {str} -- API Endpoint without base url.
            params {dict} -- Url params
            data {dict} -- Json data payload

        Returns:
            tuple -- Response to url and http code
        """
        full_path = f"{self.base_url}{path}"
        header['X-API-KEY'] = token
        if method.upper() in requests.options(full_path).headers['allow']:
            response = getattr(requests, method.lower())(
                full_path,
                params=params,
                data=json.dumps(data),
                headers=header
            )
        else:
            response = {"message": "Method not allowed"}, 405
        return response.text, response.status_code
