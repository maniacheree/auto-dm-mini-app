import hashlib
import hmac
import json
import time
from urllib.parse import parse_qsl


def verify_telegram_init_data(init_data: str, bot_token: str, max_age: int = 86400):
    if not init_data or not bot_token:
        return None, "Missing initData or bot token"

    try:
        data = dict(parse_qsl(init_data, keep_blank_values=True))
        received_hash = data.pop("hash", None)

        if not received_hash:
            return None, "Missing Telegram hash"

        data_check_string = "\n".join(
            f"{key}={data[key]}"
            for key in sorted(data)
        )

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

        if not hmac.compare_digest(calculated_hash, received_hash):
            return None, "Invalid Telegram signature"

        auth_date = int(data.get("auth_date", "0"))

        if auth_date <= 0:
            return None, "Invalid auth date"

        if time.time() - auth_date > max_age:
            return None, "Telegram authorization expired"

        user_raw = data.get("user")

        if not user_raw:
            return None, "Telegram user data missing"

        user = json.loads(user_raw)

        return user, None

    except Exception as e:
        return None, f"Verification error: {str(e)}"
