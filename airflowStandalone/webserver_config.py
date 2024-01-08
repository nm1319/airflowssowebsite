from typing import Any, Callable

from flask import current_app
from flask_appbuilder.const import AUTH_REMOTE_USER
import requests

class CustomMiddleware():
    def __init__(self, wsgi_app: Callable) -> None:
        self.wsgi_app = wsgi_app

    def __call__(self, environ: dict, start_response: Callable) -> Any:
        # Custom authenticating logic here
        # ...
        resp = requests.get('http://172.17.0.3:5000/fetch')
        data1 = resp.json()
        print(data1)
        email=data1.get("email", "")
        username=email.split('@')[0]
        print('***NPM*** I am in custom SecurityManager')
        print(username)
        environ["REMOTE_USER"] = username
        return self.wsgi_app(environ, start_response)


current_app.wsgi_app = CustomMiddleware(current_app.wsgi_app)

AUTH_TYPE = AUTH_REMOTE_USER
#AUTH_ROLES_SYNC_AT_LOGIN = False
