import os
import time
import json
import hmac
import hashlib
import urllib.parse

from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

BOT_TOKEN = os.getenv("BOT_TOKEN")

# Temporary verification state.
# No OTP, 2FA password, or Telegram session string is stored.
verified_users = {}


def verify_telegram_init_data(init_data, bot_token):
    try:
        if not init_data:
            return None, "Missing Telegram initData"

        if not bot_token:
            return None, "BOT_TOKEN is not configured"

        parsed = urllib.parse.parse_qs(
            init_data,
            keep_blank_values=True
        )

        received_hash = parsed.get("hash", [None])[0]

        if not received_hash:
            return None, "Missing Telegram hash"

        data_check_parts = []

        for key in sorted(parsed.keys()):
            if key == "hash":
                continue

            value = parsed[key][0]
            data_check_parts.append(
                f"{key}={value}"
            )

        data_check_string = "\n".join(
            data_check_parts
        )

        secret_key = hmac.new(
            b"WebAppData",
            bot_token.encode("utf-8"),
            hashlib.sha256
        ).digest()

        calculated_hash = hmac.new(
            secret_key,
            data_check_string.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(
            calculated_hash,
            received_hash
        ):
            return None, "Invalid Telegram signature"

        auth_date_raw = parsed.get(
            "auth_date",
            [None]
        )[0]

        if not auth_date_raw:
            return None, "Missing auth_date"

        try:
            auth_date = int(auth_date_raw)
        except ValueError:
            return None, "Invalid auth_date"

        # Telegram Mini App data older than 24 hours is rejected.
        if time.time() - auth_date > 86400:
            return None, "Telegram authorization expired"

        user_raw = parsed.get(
            "user",
            [None]
        )[0]

        if not user_raw:
            return None, "Telegram user data missing"

        try:
            telegram_user = json.loads(user_raw)
        except json.JSONDecodeError:
            return None, "Invalid Telegram user data"

        if not telegram_user.get("id"):
            return None, "Telegram user ID missing"

        return telegram_user, None

    except Exception as error:
        return None, f"Verification error: {str(error)}"


# ==========================================
# HOME
# ==========================================

@app.get("/")
def home():
    return jsonify({
        "status": "online",
        "service": "Auto DM Mini App Backend"
    })


# ==========================================
# HEALTH
# ==========================================

@app.get("/health")
def health():
    return jsonify({
        "status": "ok"
    })


# ==========================================
# VERIFY TELEGRAM MINI APP
# ==========================================

@app.post("/api/verify")
def verify():

    if not BOT_TOKEN:
        return jsonify({
            "ok": False,
            "error": "BOT_TOKEN is not configured"
        }), 500

    body = request.get_json(
        silent=True
    ) or {}

    init_data = body.get("initData")

    if not init_data:
        return jsonify({
            "ok": False,
            "error": "Telegram initData is required"
        }), 400

    telegram_user, error = verify_telegram_init_data(
        init_data,
        BOT_TOKEN
    )

    if error:
        return jsonify({
            "ok": False,
            "error": error
        }), 401

    user_id = str(
        telegram_user["id"]
    )

    verified_users[user_id] = {
        "verified": True,
        "verified_at": int(time.time()),
        "user": {
            "id": telegram_user.get("id"),
            "first_name": telegram_user.get(
                "first_name",
                ""
            ),
            "last_name": telegram_user.get(
                "last_name",
                ""
            ),
            "username": telegram_user.get(
                "username",
                ""
            )
        }
    }

    return jsonify({
        "ok": True,
        "verified": True,
        "user": verified_users[user_id]["user"]
    })


# ==========================================
# CHECK VERIFICATION STATUS
# ==========================================

@app.get("/api/status/<user_id>")
def verification_status(user_id):

    user_id = str(user_id)

    data = verified_users.get(user_id)

    if not data:
        return jsonify({
            "ok": True,
            "verified": False
        })

    # Verification expires after 24 hours.
    verified_at = data.get(
        "verified_at",
        0
    )

    if time.time() - verified_at > 86400:

        verified_users.pop(
            user_id,
            None
        )

        return jsonify({
            "ok": True,
            "verified": False
        })

    return jsonify({
        "ok": True,
        "verified": True,
        "user": data["user"]
    })


# ==========================================
# LOGOUT / CLEAR VERIFICATION
# ==========================================

@app.post("/api/logout/<user_id>")
def logout(user_id):

    verified_users.pop(
        str(user_id),
        None
    )

    return jsonify({
        "ok": True,
        "verified": False
    })


# ==========================================
# START SERVER
# ==========================================

if __name__ == "__main__":

    port = int(
        os.getenv(
            "PORT",
            "8080"
        )
    )

    app.run(
        host="0.0.0.0",
        port=port
    )
