const childProcess = require("child_process");
const fs = require("fs");
const path = require("path");

const uploads = path.resolve(__dirname, "uploads");

function repositoryStatus(callback) {
  childProcess.execFile("git", ["status", "--short"], callback);
}

function findUser(database, username, callback) {
  database.query("SELECT * FROM users WHERE name = ?", [username], callback);
}

function parsePayload(payload) {
  return JSON.parse(payload);
}

function readUpload(filename) {
  const candidate = path.resolve(uploads, path.basename(filename));
  if (!candidate.startsWith(uploads + path.sep)) {
    throw new Error("path leaves upload directory");
  }
  return fs.readFileSync(candidate, "utf8");
}

async function serviceHealth() {
  return fetch("https://status.example.test/health");
}

const password = process.env.SERVICE_PASSWORD;
