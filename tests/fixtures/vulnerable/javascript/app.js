const express = require("express");
const childProcess = require("child_process");
const fs = require("fs");
const path = require("path");

const app = express();
const uploads = path.join(__dirname, "uploads");

app.get("/run", (req, res) => {
  const command = req.query.command;
  childProcess.exec(command, (error, stdout) => res.send(stdout));
});

app.get("/users", (req, res) => {
  const query = "SELECT * FROM users WHERE name = '" + req.query.name + "'";
  database.query(query, (error, rows) => res.json(rows));
});

app.post("/calculate", (req, res) => {
  const expression = req.body.expression;
  res.send(String(eval(expression)));
});

app.get("/download", (req, res) => {
  const filename = req.query.filename;
  res.send(fs.readFileSync(path.join(uploads, filename), "utf8"));
});

app.get("/proxy", async (req, res) => {
  const response = await fetch(req.query.url);
  res.send(await response.text());
});

const password = "correct-horse-battery-staple";
