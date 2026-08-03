/*
 * vuln-app.js - a deliberately vulnerable demo Express app used ONLY to test
 * VulnHunter's multi-language scanner coverage. DO NOT deploy this anywhere. It
 * contains intentional security flaws for demonstration purposes only.
 *
 * Planted vulnerabilities (for scoring / demo reference):
 *   1. Command injection via child_process.exec       -> CWE-78
 *   2. Reflected XSS via unsanitized template string   -> CWE-79
 *   3. Hardcoded API key                                -> CWE-798
 */

const express = require("express");
const { exec } = require("child_process");

const app = express();

// VULN 3: Hardcoded secret (CWE-798) - should come from process.env / a secrets manager
const STRIPE_API_KEY = "sk_live_DEMO_FAKE_NOT_A_REAL_KEY_9876543210";

app.get("/ping", (req, res) => {
  // VULN 1: Command injection (CWE-78) - user-controlled host is interpolated
  // straight into a shell command string instead of using execFile with an args array.
  const host = req.query.host || "127.0.0.1";
  exec(`ping -c 1 ${host}`, (err, stdout, stderr) => {
    if (err) {
      res.status(500).send("ping failed");
      return;
    }
    res.send(stdout);
  });
});

app.get("/greet", (req, res) => {
  // VULN 2: Reflected XSS (CWE-79) - user-controlled "name" is concatenated directly
  // into an HTML response template string with no escaping, equivalent to assigning
  // untrusted data straight into innerHTML on the client.
  const name = req.query.name || "guest";
  const page = `<html><body><h1>Welcome back, ${name}!</h1></body></html>`;
  res.set("Content-Type", "text/html");
  res.send(page);
});

app.get("/charge", (req, res) => {
  // Demonstrates the hardcoded key actually being used.
  const amount = req.query.amount;
  res.json({ status: "charged", amount, key_used: STRIPE_API_KEY.slice(0, 10) + "..." });
});

app.listen(3000, () => {
  console.log("vuln-app listening on port 3000");
});

module.exports = app;
