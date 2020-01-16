//main starting point of the application

const express = require("express");
const http = require("http");
const bodyParser = require("body-parser");
const morgan = require("morgan");
const router = require("./router");
const keys = require("./config/keys");

const app = express();

//App Setup, Express Server Setup
//morgan and bodyParser are middleware in express.
//morgan is a logging framework, logs for debugging
//bodyParser parses incoming requests as JSON. might present problems later for transfering files.
app.use(morgan("combined"));
app.use(bodyParser.json({ type: "*/*" }));
router(app);

//Server Setup, Express talking to the outside world
const port = process.env.PORT || 3090;
const server = http.createServer(app);
server.listen(port);
console.log("Server listening on port: ", port);
