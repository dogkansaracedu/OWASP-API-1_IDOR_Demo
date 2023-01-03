import os
from dotenv import load_dotenv
from flask import Flask, request
from pymongo import MongoClient
import bcrypt
import jwt
import json
from bson import json_util, ObjectId

load_dotenv()

app = Flask(__name__)

jwt_secret = os.environ.get("JWT_SECRET")
client = MongoClient(os.environ.get("MONGODB_URI"))
db = client[os.environ.get("DB_NAME")]

# Util
def _get_successful_create_response(object):
    return f"{object} successfully created.", 201


def _parse_json(data):
    return json.loads(json_util.dumps(data))


def _get_credentials(auth_header):
    token = auth_header.split()[1]
    return jwt.decode(token, jwt_secret, algorithms=["HS256"])

def _get_userID(auth_header):
    if auth_header is None:
        return None

    credentials = _get_credentials(auth_header)

    return credentials["id"]

_message_successfully_created_response = _get_successful_create_response("Message")
_user_not_authorized_response = "User is not authorized", 401
_message_max_length = 1000


# Secure Message Requests
@app.route("/", methods=["POST"])
def add_message():
    message = request.args.get("message")

    if (
        message is None
        or message.strip() == ""
        or len(message.strip()) > _message_max_length
    ):
        return f"Message length must be 1 to  {_message_max_length}", 400

    userID = _get_userID(request.headers.get("Authorization"))
    if userID:
        messages = db.messages
        messages.insert_one(
            {
                "userID": userID,
                "content": message.strip(),
            }
        )
    else:
        return _user_not_authorized_response

    return _message_successfully_created_response


@app.route("/<messageID>", methods=["GET"])
def get_message(messageID: str):
    if len(messageID) != 24:  # id must be 24 chars hex string
        return "Message not found", 404

    userID = _get_userID(request.headers.get("Authorization"))
    if userID:
        messages = db.messages
        message = messages.find_one({"_id": ObjectId(messageID), "userID": userID})
    else:
        return _user_not_authorized_response

    if message is None:
        return "Message not found", 404
    return f"{message}"


# Vulnerable Message Requests
@app.route("/vulnerable", methods=["POST"])
def vulnerable_add_message():
    predictableUserID = request.args.get("predictableUserID")
    message = request.args.get("message")

    messages = db.messages

    id = (
        messages.find({"predictableUserID": int(predictableUserID)})
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
            "predictableUserID": int(predictableUserID),
            "content": message,
        }
    )

    return _message_successfully_created_response


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
    password = request.args.get("password")
    if username is None or password is None:
        return "Please provide your credentials", 400

    users = db.users
    user = users.find_one({"username": username})

    if user is None or not bcrypt.checkpw(
        password.encode("utf-8"), user["passwordHash"]
    ):
        return "Credentials are incorrect", 400

    encoded_jwt = jwt.encode(
        {"id": _parse_json(user["_id"])["$oid"]}, jwt_secret
    )  # _id is object and needs to be parsed

    return f"{encoded_jwt}", 201


@app.route("/register", methods=["POST"])
def register():
    username = request.args.get("username")
    password = request.args.get("password")

    if username is None or password is None:
        return "Please provide your credentials", 400

    if len(password) < 8 or len(password) > 32:
        return "Password must have 8 to 32 characters", 400

    users = db.users
    user = users.find_one({"username": username}, None)

    if user is not None:
        return "User already exists", 409

    salt = bcrypt.gensalt()
    hash = bcrypt.hashpw(password.encode("utf-8"), salt)

    predictableID = users.find().sort("predictableID", -1).limit(1)
    predictableID = predictableID[0]["predictableID"] + 1

    users.insert_one({"predictableID": predictableID, "username": username, "passwordHash": hash})

    return f"{username} successfully created.", 201


@app.route("/add-dummy-messages", methods=["POST"])
def addDummyMessages():
    predictableUserID = request.args.get("userID")
    numOfMessages = int(request.args.get("numberOfMessages"))
    
    messages = db.messages
    users = db.users

    user = (
        users.find_one({"predictableID": int(predictableUserID)})
    )
    print(user)
    if (user == None):
        username = f"user {predictableUserID}"
        password = f"password{predictableUserID}"

        salt = bcrypt.gensalt()
        hash = bcrypt.hashpw(password.encode("utf-8"), salt)


        users.insert_one({"predictableID": int(predictableUserID), "username": username, "passwordHash": hash})
        user = users.find_one({"predictableID": int(predictableUserID)})

    print(user)


    id = (
        messages.find({"predictableUserID": int(predictableUserID)})
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
                "userID": user['_id'],
                "predictableID": id,
                "predictableUserID": int(predictableUserID),
                "content": f"Message {id}",
            }
        )
        id += 1
    return f"{numOfMessages} messages successfully created.", 201
