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


@app.route("/vulnerable/<userID>/<messageID>")
def get_message(userID, messageID):
    messages = db.messages
    message = messages.find_one({"_id": messageID})

    return f"{message}"


def parse_json(data):
    return json.loads(json_util.dumps(data))


@app.route("/login", methods=["GET"])
def login():
    username = request.args.get("username")
    password = request.args.get("password").encode("utf-8")

    users = db.users
    user = users.find_one({"username": username})

    if user is None or not bcrypt.checkpw(password, user["passwordHash"]):
        return "Credentials are incorrect", 400

    encoded_jwt = jwt.encode({"_id": parse_json(user["_id"])}, jwt_secret) #_id is object and needs to be parsed

    return f"{encoded_jwt}"


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
