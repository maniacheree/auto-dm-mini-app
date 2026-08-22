import os
from flask import Flask, request, jsonify
from miniapp import verify_telegram_init_data

app = Flask(__name__)

BOT_TOKEN = os.getenv("BOT_TOKEN")


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
