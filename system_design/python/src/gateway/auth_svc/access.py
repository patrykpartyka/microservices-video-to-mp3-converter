import http, os, requests


AUTH_SVC_ADDRESS = os.environ.get("AUTH_SVC_ADDRESS")


def login(request):
    auth = request.authorization
    if not auth:
        return None, ("missing credentials", http.HTTPStatus.UNAUTHORIZED)

    basicAuth = (auth.username, auth.password)

    response = requests.post(url=f"http://{AUTH_SVC_ADDRESS}/login", auth=basicAuth)

    if response.status_code == http.HTTPStatus.OK:
        return response.text, None
    else:
        return None, (response.text, response.status_code)
