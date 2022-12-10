import os
from dotenv import load_dotenv
from flask import Flask, request
from pymongo import MongoClient
load_dotenv()

app = Flask(__name__)

client = MongoClient(os.environ.get('MONGODB_URI'))

db = client[os.environ.get('DB_NAME')]
todos = db.todos


@app.route("/vulnerable/<userID>/<messageID>")
def hello_world(userID, messageID):
    messages = db.messages
    message = messages.find_one({"_id": messageID})
    print(message)
    return f"{message}"