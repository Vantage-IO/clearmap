// Express must-NOT-catch near-misses for rules/access.yaml.
const express = require("express");
const jwt = require("jsonwebtoken");
const { requireAuth } = require("./middleware");

const app = express();

// NEAR-MISS: inline auth middleware ahead of the handler.
app.get("/patients/:id", requireAuth, (req, res) => {
  res.json({ id: req.params.id });
});

// NEAR-MISS: non-PHI route with a bare handler stays silent.
app.get("/healthz", (req, res) => {
  res.send("ok");
});

// NEAR-MISS: token signed with an expiry.
function issueToken(userId) {
  return jwt.sign({ sub: userId }, process.env.JWT_SECRET, { expiresIn: "15m" });
}

module.exports = { app, issueToken };
