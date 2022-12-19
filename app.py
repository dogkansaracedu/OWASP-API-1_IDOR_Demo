import os
from dotenv import load_dotenv
from flask import Flask, request
from pymongo import MongoClient
import bcrypt
import jwt
import json
from bson import json_util

load_dotenv()

app = Flask(__name__)

jwt_secret = os.environ.get("JWT_SECRET")
client = MongoClient(os.environ.get("MONGODB_URI"))
db = client[os.environ.get("DB_NAME")]

# Util


def parse_json(data):
    return json.loads(json_util.dumps(data))


# Secure Message Requests


@app.route("/", methods=["POST"])
def add_message():
    token = request.headers.get("Authorization").split()[1]
    credentials = jwt.decode(token, jwt_secret, algorithms=["HS256"])
    message = request.args.get("message")

    messages = db.messages

    messages.insert_one(
        {
            "userID": credentials["_id"],
            "content": message,
        }
    )

    return "Message successfully created.", 201


@app.route("/<messageID>", methods=["GET"])
def get_message(messageID):
    messages = db.messages

    token = request.headers.get("Authorization").split()[1]
    credentials = jwt.decode(token, jwt_secret, algorithms=["HS256"])

    userID = credentials["_id"]
    if userID:
        message = messages.find_one({"_id": messageID, "userID": userID})

    return f"{message}"


# Vulnerable Message Requests


@app.route("/vulnerable", methods=["POST"])
def vulnerable_add_message():
    predictableUserID = request.args.get("predictableUserID")
    message = request.args.get("message")

    messages = db.messages

    id = (
        messages.find({"userID": int(predictableUserID)})
        .sort("predictableID", -1)
        .limit(1)
    )

    items = id.clone()
    if len(list(items)) > 0:
        id = id[0]["predictableID"] + 1
    else:
        id = 0

    messages.insert_one(
        {
            "predictableID": id,
            "userID": int(predictableUserID),
            "content": message,
        }
    )

    return "Message successfully created.", 201


@app.route("/vulnerable/<userID>/<messageID>", methods=["GET"])
def vulnerable_get_message(userID, messageID):
    messages = db.messages
    message = messages.find_one(
        {"predictableID": int(messageID), "predictableUserID": int(userID)}
    )

    return f"{message}"


# Auth


@app.route("/login", methods=["POST"])
def login():
    username = request.args.get("username")
    password = request.args.get("password").encode("utf-8")

    users = db.users
    user = users.find_one({"username": username})

    if user is None or not bcrypt.checkpw(password, user["passwordHash"]):
        return "Credentials are incorrect", 400

    encoded_jwt = jwt.encode(
        {"_id": parse_json(user["_id"]), "is_admin": user["is_admin"]}, jwt_secret
    )  # _id is object and needs to be parsed

    return f"{encoded_jwt}", 201


@app.route("/register", methods=["POST"])
def register():
    username = request.args.get("username")
    password = request.args.get("password").encode("utf-8")

    users = db.users
    user = users.find_one({"username": username})

    if user is not None:
        return "User already exists", 409

    salt = bcrypt.gensalt()
    hash = bcrypt.hashpw(password, salt)

    id = users.find().sort("predictableID", -1).limit(1)
    id = id[0]["predictableID"] + 1

    users.insert_one({"predictableID": id, "username": username, "passwordHash": hash})

    return f"{username} successfully created.", 201
