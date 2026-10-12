import ast
import os
import sqlite3
import subprocess
from pathlib import Path

import requests
import yaml


DATABASE = sqlite3.connect("app.db")
UPLOAD_ROOT = Path("uploads").resolve()


def repository_status():
    return subprocess.run(["git", "status", "--short"], check=True, capture_output=True)


def find_user(username):
    return list(DATABASE.execute("SELECT * FROM users WHERE username = ?", (username,)))


def parse_expression(expression):
    return ast.literal_eval(expression)


def read_upload(filename):
    candidate = (UPLOAD_ROOT / Path(filename).name).resolve()
    if UPLOAD_ROOT not in candidate.parents:
        raise ValueError("path leaves upload directory")
    return candidate.read_text()


def service_health():
    return requests.get("https://status.example.test/health", timeout=2)


def load_settings(data):
    return yaml.safe_load(data)


API_KEY = os.environ["API_KEY"]
