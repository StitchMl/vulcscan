from flask import Flask, request
import pickle
import sqlite3
import subprocess
from pathlib import Path

import requests


app = Flask(__name__)
DATABASE = sqlite3.connect("app.db")
UPLOAD_ROOT = Path("uploads")


@app.get("/run")
def run_command():
    command = request.args["command"]
    subprocess.run(command, shell=True)
    return "started"


@app.get("/users")
def find_user():
    username = request.args["username"]
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    return list(DATABASE.execute(query))


@app.post("/calculate")
def calculate():
    expression = request.form["expression"]
    return str(eval(expression))


@app.get("/download")
def download():
    filename = request.args["filename"]
    return (UPLOAD_ROOT / filename).read_text()


@app.get("/proxy")
def proxy():
    url = request.args["url"]
    return requests.get(url, timeout=2).text


@app.post("/restore")
def restore():
    return repr(pickle.loads(request.data))


API_KEY = "prod_live_1234567890abcdef"
