import os
from dotenv import load_dotenv
from flask import Flask, request
from pymongo import MongoClient
import bcrypt

load_dotenv()

app = Flask(__name__)

client = MongoClient(os.environ.get("MONGODB_URI"))

db = client[os.environ.get("DB_NAME")]
todos = db.todos


@app.route("/vulnerable/<userID>/<messageID>")
def get_message(userID, messageID):
    messages = db.messages
    message = messages.find_one({"_id": messageID})

    return f"{message}"


@app.route("/register", methods=["POST"])
def register():
    username = request.args.get("username")
    password = request.args.get("password")

    users = db.users
    user = users.find_one({"_id": username})

    if user is not None:
        return "User already exists", 409

    salt = bcrypt.gensalt()
    password = password.encode("utf-8")
    hash = bcrypt.hashpw(password, salt)

    id = users.find().sort("_id", -1).limit(1)

    id = int(id[0]["_id"]) + 1

    users.insert_one({"_id": id, "username": username, "passwordHash": hash})

    return f"{username} successfully created.", 201