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
def get_successful_create_response(object):
    return f"{object} successfully created.", 201


def parse_json(data):
    return json.loads(json_util.dumps(data))


def get_credentials(token: str):
    return jwt.decode(token, jwt_secret, algorithms=["HS256"])


user_not_authorized_response = "User is not authorized", 401
message_successfully_created_response = get_successful_create_response("Message")


# Secure Message Requests


@app.route("/", methods=["POST"])
def add_message():
    token = request.headers.get("Authorization").split()[1]
    credentials = get_credentials(token)
    message = request.args.get("message")

    if message is None or message.strip() is "":
        return "Please specify a message", 400

    userID = credentials["_id"]
    if userID:
        messages = db.messages
        messages.insert_one(
            {
                "userID": credentials["_id"],
                "content": message,
            }
        )
    else:
        return user_not_authorized_response

    return message_successfully_created_response


@app.route("/<messageID>", methods=["GET"])
def get_message(messageID: str):
    token = request.headers.get("Authorization").split()[1]
    credentials = get_credentials(token)

    userID = credentials["_id"]
    if userID:
        messages = db.messages
        message = messages.find_one({"_id": messageID, "userID": userID})
    else:
        return user_not_authorized_response

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

    return message_successfully_created_response


@app.route("/vulnerable/<userID>/<messageID>", methods=["GET"])
def vulnerable_get_message(user_id, messageID):
    messages = db.messages
    message = messages.find_one(
        {"predictableID": int(messageID), "predictableUserID": int(user_id)}
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
    if password is None or len(password) < 8 or len(password) > 32:
        return "Password must have 8 to 32 characters", 400

    salt = bcrypt.gensalt()
    hash = bcrypt.hashpw(password, salt)

    id = users.find().sort("predictableID", -1).limit(1)
    id = id[0]["predictableID"] + 1

    users.insert_one({"predictableID": id, "username": username, "passwordHash": hash})

    return f"{username} successfully created.", 201


@app.route("/add-dummy-messages", methods=["POST"])
def addDummyMessages():
    userID = request.args.get("userID")
    numOfMessages = int(request.args.get("numberOfMessages"))

    messages = db.messages

    id = (
        messages.find({"predictableUserID": int(userID)})
        .sort("predictableID", -1)
        .limit(1)
    )

    items = id.clone()
    if len(list(items)) > 0:
        id = id[0]["predictableID"] + 1
    else:
        id = 0

    for i in range(numOfMessages):
        messages.insert_one(
            {
                "predictableID": id,
                "predictableUserID": int(userID),
                "content": f"Message {id}",
            }
        )
        id += 1
    return 201
