import os, requests, http


AUTH_SVC_ADDRESS = os.environ.get("AUTH_SVC_ADDRESS")


def token(request):
    if not "Authorization" in request.headers:
        return None, ("missing credentials", http.HTTPStatus.UNAUTHORIZED)

    token = request.headers["Authorization"]

    if not token:
        return None, ("missing credentials", http.HTTPStatus.UNAUTHORIZED)

    response = requests.post(
        f"http://{AUTH_SVC_ADDRESS}/validate",
        headers={"Authorization": token},
    )

    if response.status_code == http.HTTPStatus.OK:
        return response.text, None
    else:
        return None, (response.text, response.status_code)
