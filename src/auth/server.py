import jwt, datetime, os
from flask import Flask, request
from flask_mysqldb import MySQL
from datetime import datetime, timedelta, timezone


server = Flask(__name__)
mysql = MySQL(server)

#config
server.config["MYSQL_HOST"] = os.environ.get("MYSQL_HOST")
server.config["MYSQL_USER"] = os.environ.get("MYSQL_USER")
server.config["MYSQL_PASSWORD"] = os.environ.get("MYSQL_PASSWORD")
server.config["MYSQL_DB"] = os.environ.get("MYSQL_DB")
server.config["MYSQL_PORT"] = os.environ.get("MYSQL_PORT")
# print(server.config["MYSQL_HOST"])

@server.route("/login", methods=["POST"])
def login():
    auth = request.authorization

    if not auth:
        return "missing credentials", 401
    
    """ Check the database for existing username and password"""

    cur = mysql.connection.cursor()
    # we use the cursor to make queries 
    res = cur.execute(
        "SELECT email, password FROM user WHERE email=%s",  (auth.username)
    )

    if res > 0:
        user_row = cur.fetchone()
        email = user_row[0]
        password = user_row[1]

        if auth.username != email or auth.password != password:
            return "invalid credentials", 401
        else:
            return createJWT(auth.username, os.environ.get("SECRET_KEY"), True)
    # this means that the user doesnt exist in the database 
    else:
        return "invalid credentials", 401

@server.route("/validate", methods=["POST"])  
def validateJWT():
    encoded_jwt = request.headers["Authorization"]

    if not encoded_jwt:
        return "missing credentials", 401
    
    else:
        # The encoded jwt will be of the form Authorization: <Bearer> <Token>
        encoded_jwt_token = encoded_jwt.split(" ")[1]

        try:
            decoded = jwt.decode(
                encoded_jwt_token, 
                os.environ.get("JWT_SECRET"), 
                algorithm = ["HS256"]
            )
        except:
            return "Not authorized", 403
        
        return decoded, 200



def createJWT(username, secret, authz):
    encodedJWT = jwt.encode(
        {
            "username": username,
            "exp": datetime.now(timezone.utc) + timedelta(minutes=os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES")),
            "iat": datetime.now(timezone.utc),
            "admin": authz,
        },
        secret,
        algorithm="HS256",
    )
    return encodedJWT



if __name__ == "__main__":
    server.run(host="0.0.0.0", port=5000)
    
    

    