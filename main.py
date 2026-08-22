import os
import hashlib
import hmac
import json
import urllib.parse

from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

BOT_TOKEN = os.getenv("BOT_TOKEN")


def verify_telegram_init_data(init_data, bot_token):
    try:
        parsed = urllib.parse.parse_qs(
            init_data,
            keep_blank_values=True
        )

        received_hash = parsed.get("hash", [None])[0]

        if not received_hash:
            return None, "Missing Telegram hash"

        data_check = []

        for key in sorted(parsed.keys()):
            if key == "hash":
                continue

            value = parsed[key][0]
            data_check.append(f"{key}={value}")

        data_check_string = "\n".join(data_check)

        secret_key = hmac.new(
            b"WebAppData",
            bot_token.encode(),
            hashlib.sha256
        ).digest()

        calculated_hash = hmac.new(
            secret_key,
            data_check_string.encode(),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(
            calculated_hash,
            received_hash
        ):
            return None, "Invalid Telegram signature"

        user_raw = parsed.get("user", [None])[0]

        if not user_raw:
            return None, "Telegram user data missing"

        user = json.loads(user_raw)

        return user, None

    except Exception as e:
        return None, f"Verification error: {str(e)}"


@app.get("/")
def home():
    return jsonify({
        "status": "online",
        "service": "Auto DM Mini App Backend"
    })


@app.get("/health")
def health():
    return jsonify({
        "status": "ok"
    })


@app.post("/api/verify")
def verify():

    if not BOT_TOKEN:
        return jsonify({
            "ok": False,
            "error": "BOT_TOKEN is not configured"
        }), 500

    body = request.get_json(silent=True) or {}

    init_data = body.get("initData")

    if not init_data:
        return jsonify({
            "ok": False,
            "error": "Telegram initData is required"
        }), 400

    user, error = verify_telegram_init_data(
        init_data,
        BOT_TOKEN
    )

    if error:
        return jsonify({
            "ok": False,
            "error": error
        }), 401

    return jsonify({
        "ok": True,
        "verified": True,
        "user": {
            "id": user.get("id"),
            "first_name": user.get("first_name"),
            "last_name": user.get("last_name"),
            "username": user.get("username")
        }
    })


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))

    app.run(
        host="0.0.0.0",
        port=port
    )
