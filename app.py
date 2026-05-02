"""
CTF Challenge - Main Application (Render-compatible single-service build)

Both the main app and the "internal" service run in the same process.
The internal routes are gated by a loopback-only check, so they are only
reachable via SSRF — not directly from a browser.

Render assigns the port via the PORT environment variable (default 10000).
SSRF target: http://127.0.0.1:<PORT>/internal-svc/internal
"""

from flask import Flask, request, jsonify, make_response, send_from_directory
from flask_cors import CORS
import base64
import requests as req_lib
import jwt
import os
import codecs

app = Flask(__name__, static_folder="static", static_url_path="/static")
CORS(app, supports_credentials=True)

# ─────────────────────────────────────────────
# Weak JWT secret — intentionally vulnerable
# ─────────────────────────────────────────────
JWT_SECRET = "weaksecret"
JWT_ALGORITHM = "HS256"

# Render exposes the app on $PORT (usually 10000)
PORT = int(os.environ.get("PORT", 10000))


# ══════════════════════════════════════════════
# SERVE FRONTEND
# ══════════════════════════════════════════════

@app.route("/")
def index():
    return send_from_directory("static", "index.html")


# ══════════════════════════════════════════════
# STAGE 1 — LOGIN (Logic Flaw + Misdirection)
# ══════════════════════════════════════════════
# Hint in source: "SELECT * FROM users WHERE username='?' AND password='?'"
# Reality: no database — pure Python logic

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    # <!-- SQL-like comment to mislead: try ' OR '1'='1 -->
    # Real check has nothing to do with SQL injection
    if "admin" in username.lower():
        resp = make_response(jsonify({
            "status": "success",
            "message": "Welcome, administrator.",
            "token_hint": "Part1: HW{@_",
            "debug": "Query executed: SELECT * FROM users WHERE id=1"
        }))
        resp.set_cookie("role", "user", httponly=False)
        return resp

    if "'" in username or "--" in username or "OR" in username.upper():
        return jsonify({
            "status": "error",
            "message": "SQL Error: syntax error near unexpected token",
            "debug": "Hint: maybe the check isn't SQL at all..."
        }), 401

    return jsonify({
        "status": "error",
        "message": "Invalid credentials.",
        "debug": "Try harder. The query is: SELECT * FROM users WHERE username=? AND password=?"
    }), 401


# ══════════════════════════════════════════════
# STAGE 2 — CRYPTO (Noise vs Real)
# ══════════════════════════════════════════════

@app.route("/crypto", methods=["GET"])
def crypto():
    real_b64    = base64.b64encode(b"NICE_").decode()
    fake_hex    = "6e6f7468696e675f68657265"
    fake_rot13  = codecs.encode("wrong_path", "rot_13")
    fake_double = base64.b64encode(
        base64.b64encode(b"red_herring_lol").decode().encode()
    ).decode()
    fake_extra  = base64.b64encode(b"almost_NICE").decode()

    return jsonify({
        "encoded_strings": [
            {"id": "A", "type": "unknown", "value": fake_hex},
            {"id": "B", "type": "unknown", "value": real_b64},
            {"id": "C", "type": "unknown", "value": fake_rot13},
            {"id": "D", "type": "unknown", "value": fake_double},
            {"id": "E", "type": "unknown", "value": fake_extra},
        ],
        "note": "One of these strings contains the next fragment. Encoding type not disclosed."
    })


# ══════════════════════════════════════════════
# STAGE 3 — RECON (Fake routes / misdirection)
# ══════════════════════════════════════════════

@app.route("/backup", methods=["GET"])
def backup():
    return jsonify({
        "status": "found",
        "message": "Backup service online.",
        "flag": "HW{fake_backup_flag}",
        "note": "Nothing useful here. Keep scanning."
    })

@app.route("/old-admin", methods=["GET"])
def old_admin():
    return jsonify({
        "status": "deprecated",
        "message": "This endpoint was removed in v2.",
        "flag": "HW{not_this_one}",
        "hint": "The real admin panel moved... somewhere else."
    })

@app.route("/test-api", methods=["GET"])
def test_api():
    return jsonify({
        "status": "ok",
        "version": "0.9-beta",
        "flag": "HW{almost_there_but_no}",
        "services": ["web:main", "???:????"],
        # Subtle hint: there's an internal sub-path
        "hint": "There might be an internal service path. Have you tried everything?"
    })


# ══════════════════════════════════════════════
# STAGE 4 — SSRF (Pivot to internal sub-path)
# ══════════════════════════════════════════════
# On Render, both services share one port.
# SSRF target: http://127.0.0.1:<PORT>/internal-svc/internal

@app.route("/fetch", methods=["GET"])
def fetch():
    url = request.args.get("url", "")
    if not url:
        return jsonify({"error": "Missing 'url' parameter. Try ?url=http://..."}), 400

    try:
        # Intentionally no SSRF protection
        response = req_lib.get(url, timeout=5)
        return jsonify({
            "status": response.status_code,
            "body": response.text,
            "hint": "Internal services can be interesting..."
        })
    except Exception as e:
        return jsonify({
            "error": str(e),
            "hint": "Is the target reachable? Try 127.0.0.1 ranges."
        }), 500


# ══════════════════════════════════════════════
# INTERNAL SERVICE (merged — loopback-gated)
# ══════════════════════════════════════════════
# These routes mimic a separate service on port 8081.
# Access is blocked unless the request originates from 127.0.0.1
# (i.e., via SSRF through /fetch).

def _is_loopback():
    """Return True only if the request came from localhost (SSRF path)."""
    remote = request.remote_addr or ""
    # Also check X-Forwarded-For set by the internal fetch call
    forwarded = request.headers.get("X-Forwarded-For", "")
    return remote in ("127.0.0.1", "::1") or forwarded in ("127.0.0.1", "::1")


@app.route("/internal-svc/", methods=["GET"])
def internal_root():
    if not _is_loopback():
        return jsonify({"error": "Not found"}), 404
    return jsonify({
        "message": "Internal service. Nothing to see here.",
        "hint": "Try /status or look harder."
    })


@app.route("/internal-svc/status", methods=["GET"])
def internal_status():
    if not _is_loopback():
        return jsonify({"error": "Not found"}), 404
    return jsonify({"status": "ok", "service": "internal-api", "version": "1.0"})


@app.route("/internal-svc/internal", methods=["GET"])
def internal_secret():
    if not _is_loopback():
        return jsonify({"error": "Not found"}), 404
    fragment = base64.b64encode(b"SEE_").decode()
    return jsonify({
        "data": fragment,
        "encoding": "redacted",
        "note": "You found the internal service. Now decode the data."
    })


# ══════════════════════════════════════════════
# STAGE 5 — JWT (Weak secret + alg:none)
# ══════════════════════════════════════════════

@app.route("/api/token", methods=["GET"])
def get_token():
    token = jwt.encode(
        {"role": "user", "iss": "ctf-challenge"},
        JWT_SECRET,
        algorithm=JWT_ALGORITHM
    )
    return jsonify({
        "token": token,
        "algorithm": JWT_ALGORITHM,
        "hint": "Tokens are signed... but are they unbreakable?"
    })


@app.route("/api/verify", methods=["POST"])
def verify_token():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing or malformed Authorization header"}), 401

    token = auth_header.split(" ", 1)[1]

    # Vulnerability: alg:none accepted
    try:
        header = jwt.get_unverified_header(token)
        alg = header.get("alg", "").lower()
        if alg == "none":
            payload = jwt.decode(token, options={"verify_signature": False}, algorithms=["none"])
            role = payload.get("role", "")
            if role == "admin":
                return jsonify({
                    "status": "Access granted",
                    "role": role,
                    "note": "alg:none accepted. Escalation successful."
                })
            return jsonify({"status": "Access denied", "role": role}), 403
    except Exception:
        pass

    # Normal HS256 path
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        role = payload.get("role", "")
        if role == "admin":
            return jsonify({
                "status": "Access granted",
                "role": role,
                "note": "Weak secret cracked or token forged."
            })
        return jsonify({"status": "Access denied", "role": role}), 403
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError as e:
        return jsonify({"error": f"Invalid token: {str(e)}"}), 401


# ══════════════════════════════════════════════
# STAGE 6 — FINAL (Burp Suite required)
# ══════════════════════════════════════════════

@app.route("/final", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
def final():
    method_ok  = request.method == "PUT"
    xff_ok     = request.headers.get("X-Forwarded-For", "") == "127.0.0.1"
    xadmin_ok  = request.headers.get("X-Admin", "").lower() == "true"
    cookie_ok  = request.cookies.get("role", "") == "admin"

    jwt_ok = False
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]
        try:
            header = jwt.get_unverified_header(token)
            alg = header.get("alg", "").lower()
            if alg == "none":
                payload = jwt.decode(token, options={"verify_signature": False}, algorithms=["none"])
            else:
                payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            jwt_ok = payload.get("role", "") == "admin"
        except Exception:
            jwt_ok = False

    if not method_ok:
        return jsonify({"flag": "HW{fake_flag}", "hint": "Wrong method. Think about what Burp Suite can change."}), 200
    if not (xff_ok and xadmin_ok):
        return jsonify({"flag": "HW{almost_there}", "hint": "Method is right. What about your identity headers?"}), 200
    if not cookie_ok:
        return jsonify({"flag": "HW{almost_there}", "hint": "Headers look good. Check your session cookie."}), 200
    if not jwt_ok:
        return jsonify({"flag": "HW{almost_there}", "hint": "So close. Your JWT role needs elevation."}), 200

    return jsonify({
        "status": "CHALLENGE COMPLETE",
        "fragment": "YOU_BETA_..}",
        "full_flag": "HW{@_NICE_TO_SEE_YOU_BETA_..}",
        "message": "Congratulations. You've completed all stages."
    })


@app.route("/final-test", methods=["GET", "POST"])
def final_test():
    return jsonify({
        "flag": "HW{fake_final_test_flag}",
        "message": "Nice try. This isn't the real endpoint.",
        "hint": "The real final endpoint requires very specific conditions."
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=False)
