import datetime, jwt, os, http
from flask import (
    Flask,
    request,
)
from flask_mysqldb import MySQL


server = Flask(__name__)
mysql = MySQL(server)

server.config["MYSQL_HOST"] = os.environ.get("MYSQL_HOST")
server.config["MYSQL_USER"] = os.environ.get("MYSQL_USER")
server.config["MYSQL_PASSWORD"] = os.environ.get("MYSQL_PASSWORD")
server.config["MYSQL_DB"] = os.environ.get("MYSQL_DB")
server.config["MYSQL_PORT"] = int(os.environ.get("MYSQL_PORT"))


def createJWT(username: str, secret: str, is_admin: bool) -> str:
    return jwt.encode(
        payload={
            "username": username,
            "exp": datetime.datetime.now(tz=datetime.timezone.utc)
            + datetime.timedelta(days=1),
            "iat": datetime.datetime.now(tz=datetime.timezone.utc),
            "admin": is_admin,
        },
        key=secret,
        algorithm="HS256",
    )


@server.route("/login", methods=["POST"])
def login():
    auth = request.authorization
    if not auth:
        return "missing credentials", http.HTTPStatus.UNAUTHORIZED

    cursor = mysql.connection.cursor()
    result = cursor.execute(
        "SELECT email, password FROM user WHERE email=%s", (auth.username,)
    )

    if result > 0:
        user_row = cursor.fetchone()
        email = user_row[0]
        password = user_row[1]

        if auth.username != email or auth.password != password:
            return "invalid_credentials", http.HTTPStatus.UNAUTHORIZED
        else:
            return createJWT(auth.username, os.environ.get("JWT_SECRET"), True)

    else:
        return "invalid credentials", http.HTTPStatus.UNAUTHORIZED


@server.route("/validate", methods=["POST"])
def validate():
    encoded_jwt = request.headers["Authorization"]

    if not encoded_jwt:
        return "missing credentials", http.HTTPStatus.UNAUTHORIZED

    encoded_jwt = encoded_jwt.split(" ")[1]

    try:
        decoded = jwt.decode(
            encoded_jwt, os.environ.get("JWT_SECRET"), algorithms=["HS256"]
        )
    except:
        return "not authorized", http.HTTPStatus.FORBIDDEN

    return decoded, http.HTTPStatus.OK


if __name__ == "__main__":
    server.run(host="0.0.0.0", port=5000)
