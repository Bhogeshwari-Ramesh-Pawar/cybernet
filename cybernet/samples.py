"""Example code for the 'Load example' menu: each mixes real bugs with look-alike safe code,
so the ML ranking is visible. (PHP examples avoid web-shell-like snippets that antivirus flags.)"""

SAMPLES = {
    "python": '''import os
import sqlite3
import subprocess
import hashlib
import random
from flask import Flask, request, render_template_string

app = Flask(__name__)
SECRET_KEY = "Xk9#mQ2vL8pR4tW7zN1bY6cF3hJ5"   # hard-coded secret
ADMIN_PASSWORD = "changeme"                    # placeholder


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    os.system("ping -c 1 " + host)             # user input reaches the shell
    return "done"


@app.route("/users/<user_id>")
def get_user(user_id):
    db = sqlite3.connect("app.db")
    rows = db.execute(f"SELECT * FROM users WHERE id = {user_id}").fetchall()   # SQL injection
    safe = db.execute("SELECT * FROM users WHERE id = ?", (user_id,))           # parameterized: fine
    return str(rows)


@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    return "<h1>Hello " + name + "</h1>"       # reflected XSS


@app.route("/preview", methods=["POST"])
def preview():
    template = request.form["template"]
    return render_template_string(template)    # server-side template injection


def make_reset_token():
    reset_token = random.randint(100000, 999999)  # predictable
    return reset_token


def store_password(password):
    return hashlib.md5(password.encode()).hexdigest()   # weak password hash


def static_etag(content: bytes):
    return hashlib.md5(content).hexdigest()   # MD5 as a cache key: low risk


def cleanup():
    subprocess.run("rm -rf /tmp/build-cache", shell=True)   # fixed command: low risk


if __name__ == "__main__":
    app.run(debug=True)
''',
    "javascript": '''const express = require("express");
const { exec } = require("child_process");
const crypto = require("crypto");
const app = express();

const PAYMENT_API_SECRET = "Zk3pQ9vX2mL7wR4tB8nY5cF1hJ6d";   // hard-coded secret (fake demo value)
const password = "changeme";                               // placeholder

app.get("/ping", (req, res) => {
  exec(`ping -c 1 ${req.query.host}`, (err, out) => res.send(out));   // command injection
});

app.get("/users/:id", async (req, res) => {
  const rows = await db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);  // SQL injection
  const safe = await db.query("SELECT * FROM users WHERE id = ?", [req.params.id]); // parameterized
  res.json(rows);
});

app.get("/search", (req, res) => {
  res.send("<h2>Results for " + req.query.q + "</h2>");   // reflected XSS
});

app.get("/go", (req, res) => res.redirect(req.query.next));   // open redirect

function hashPassword(pw) {
  return crypto.createHash("md5").update(pw).digest("hex");   // weak password hash
}

const resetToken = Math.random().toString(36).slice(2);      // predictable token

document.getElementById("banner").innerHTML = "<b>Welcome!</b>";   // fixed HTML: low risk
document.getElementById("msg").innerHTML = location.hash.slice(1); // DOM XSS

// exec(req.query.cmd)  <- commented out, not live code
app.listen(3000);
''',
    "php": '''<?php
$db_password = "pR7#vQ2mX9kL4tZ8wB3n";        // hard-coded credential
$admin_password = "changeme";                 // placeholder

$conn = mysqli_connect("localhost", "app", $db_password, "shop");

// SQL injection: request data concatenated into the query
$result = mysqli_query($conn, "SELECT * FROM products WHERE id = " . $_GET['id']);

// Safe: prepared statement
$stmt = $conn->prepare("SELECT * FROM products WHERE id = ?");
$stmt->bind_param("i", $_GET['id']);

// Reflected XSS
echo "Search results for: " . $_GET['q'];

// Escaped output: fine
echo htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8');

// Insecure deserialization of a cookie
$prefs = unserialize($_COOKIE['prefs']);

// Weak password hashing
$hash = md5($_POST['password']);

// Cache key: low risk
$cacheKey = md5('sidebar-widget-v3');
?>
''',
    "java": '''import java.security.MessageDigest;
import java.sql.*;
import javax.crypto.Cipher;
import javax.servlet.http.*;

public class AccountServlet extends HttpServlet {
    private static final String API_SECRET = "Zq8Lm3Vt7Xr2Pk9Wn4Bs6Hc1";   // hard-coded secret

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String id = request.getParameter("id");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM accounts WHERE id = " + id);   // SQL injection

        PreparedStatement ps = conn.prepareStatement("SELECT * FROM accounts WHERE id = ?");
        ps.setString(1, id);                                                          // safe

        response.getWriter().println("Hello " + request.getParameter("name"));       // reflected XSS
    }

    String hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");                          // weak hash
        return new String(md.digest(password.getBytes()));
    }

    byte[] encrypt(byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");                         // broken cipher
        return c.doFinal(data);
    }
}
''',
}
