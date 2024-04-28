import jwt, datetime, os
from flask import Flask, request
from flask_mysqldb import MySQL


class Config:
    MYSQL_HOST = os.environ.get("MYSQL_HOST")
    MYSQL_USER = os.environ.get("MYSQL_USER")
    MYSQL_PASSWORD = os.environ.get("MYSQL_PASSWORD")
    MYSQL_DB = os.environ.get("MYSQL_DB")
    MYSQL_PORT = os.environ.get("MYSQL_PORT")
    JWT_SECRET = os.environ.get("JWT_SECRET")


server = Flask(__name__)
server.config.from_object(Config)
mysql = MySQL(server)


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


@server.route("/login", method=["POST"])
def login():
    auth = request.authorization
    if not auth:
        return "missing credentials", 401

    cursor = mysql.connection.cursor()
    result = cursor.execute(
        "SELECT email, password FROM user WHERE email=%s", (auth.username,)
    )

    if result > 0:
        user_row = cursor.fetchone()
        email = user_row[0]
        password = user_row[1]

        if auth.username != email or auth.password != password:
            return "invalid_credentials", 401
        else:
            return jwt.createJWT(auth.username, server.config["JWT_SECRET"], True)

    else:
        return "invalid credentials", 401


@server.route("/validate", method=["POST"])
def validate():
    encoded_jwt = request.headers["Authorization"]

    if not encoded_jwt:
        return "missing credentials", 401

    encoded_jwt = encoded_jwt.split(" ")[1]

    try:
        decoded = jwt.decode(
            jwt=encoded_jwt, key=server.config["JWT_SECRET"], algorithms=["HS256"]
        )
    except:
        return "non authorized", 403

    return "decoded", 200


if __name__ == "__main__":
    server.run(host="0.0.0.0", port=5000, debug=True)
