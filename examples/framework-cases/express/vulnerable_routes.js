// Express must-catch cases for rules/access.yaml.
// Verified by tests/test_access_rules.py.
const express = require("express");
const jwt = require("jsonwebtoken");

const app = express();

// MUST-CATCH access-express-unauthenticated-phi-route: bare handler, no
// inline middleware (HIGH — global app.use(auth) may exist; rule says verify).
app.get("/patients/:id", (req, res) => {
  res.json({ id: req.params.id });
});

// MUST-CATCH access-express-unauthenticated-phi-route: mutating variant.
app.patch("/patients/:id", async (req, res) => {
  res.json({ ok: true });
});

// MUST-CATCH access-jwt-no-expiry-js: two-arg sign, no expiresIn.
function issueToken(userId) {
  return jwt.sign({ sub: userId }, process.env.JWT_SECRET);
}

module.exports = { app, issueToken };
