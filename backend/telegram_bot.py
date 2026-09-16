import hashlib
import os
import time
from datetime import datetime

import httpx
from dotenv import load_dotenv

from database import SessionLocal
from models import TelegramLinkToken, User


# ============================================================
# LOAD ENVIRONMENT
# ============================================================

load_dotenv()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")

if not TELEGRAM_BOT_TOKEN:
    raise RuntimeError(
        "TELEGRAM_BOT_TOKEN is missing from backend/.env"
    )


# ============================================================
# TELEGRAM API
# ============================================================

TELEGRAM_API_URL = (
    f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"
)


# ============================================================
# TOKEN HASH
# ============================================================

def hash_token(token: str) -> str:
    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


# ============================================================
# SEND MESSAGE
# ============================================================

def send_message(chat_id: int, text: str):
    try:
        response = httpx.post(
            f"{TELEGRAM_API_URL}/sendMessage",
            json={
                "chat_id": chat_id,
                "text": text,
            },
            timeout=20,
        )

        response.raise_for_status()

        data = response.json()

        if not data.get("ok"):
            print(
                f"[Telegram] sendMessage returned an error: {data}"
            )

        return data

    except Exception as exc:
        print(
            f"[Telegram] Failed to send message: {exc}"
        )

        return None


# ============================================================
# PROCESS /START TOKEN
# ============================================================

def process_start_command(
    chat_id: int,
    telegram_username: str | None,
    token: str,
):
    db = SessionLocal()

    try:
        # ----------------------------------------------------
        # Basic diagnostics
        # IMPORTANT: Never print the real token.
        # ----------------------------------------------------

        token = token.strip()
        token_hash = hash_token(token)

        print(
            f"[Telegram] /start received | "
            f"chat_id={chat_id} | "
            f"token_length={len(token)} | "
            f"hash_prefix={token_hash[:12]}"
        )

        # ----------------------------------------------------
        # Find unused token
        # ----------------------------------------------------

        link_token = (
            db.query(TelegramLinkToken)
            .filter(
                TelegramLinkToken.token_hash == token_hash,
                TelegramLinkToken.used == False,
            )
            .first()
        )

        if not link_token:
            # ------------------------------------------------
            # Additional SAFE diagnostics.
            # We don't print the token or token_hash.
            # ------------------------------------------------

            latest_tokens = (
                db.query(TelegramLinkToken)
                .order_by(TelegramLinkToken.id.desc())
                .limit(5)
                .all()
            )

            print(
                "[Telegram] Token lookup failed | "
                f"recent_token_records={len(latest_tokens)}"
            )

            for recent in latest_tokens:
                print(
                    "[Telegram] Recent token record | "
                    f"id={recent.id} | "
                    f"user_id={recent.user_id} | "
                    f"used={recent.used} | "
                    f"expires_at={recent.expires_at}"
                )

            send_message(
                chat_id,
                "❌ This Telegram connection link is invalid or has already been used.\n\n"
                "Please generate a new connection link from the SOC Platform.",
            )
            return

        # ----------------------------------------------------
        # Token found
        # ----------------------------------------------------

        print(
            "[Telegram] Matching token found | "
            f"record_id={link_token.id} | "
            f"user_id={link_token.user_id} | "
            f"used={link_token.used} | "
            f"expires_at={link_token.expires_at}"
        )

        # ----------------------------------------------------
        # Token expired
        # ----------------------------------------------------

        now_utc = datetime.utcnow()

        if link_token.expires_at < now_utc:
            link_token.used = True
            db.commit()

            print(
                f"[Telegram] Token expired | "
                f"record_id={link_token.id} | "
                f"expired_at={link_token.expires_at} | "
                f"now={now_utc}"
            )

            send_message(
                chat_id,
                "❌ This Telegram connection link has expired.\n\n"
                "Please generate a new connection link from the SOC Platform.",
            )
            return

        # ----------------------------------------------------
        # Get SOC user
        # ----------------------------------------------------

        user = (
            db.query(User)
            .filter(
                User.id == link_token.user_id
            )
            .first()
        )

        if not user:
            link_token.used = True
            db.commit()

            print(
                "[Telegram] SOC user not found | "
                f"user_id={link_token.user_id}"
            )

            send_message(
                chat_id,
                "❌ The SOC user account associated with this link could not be found.",
            )
            return

        # ----------------------------------------------------
        # Check if another SOC account owns this Telegram chat
        # ----------------------------------------------------

        existing_user = (
            db.query(User)
            .filter(
                User.telegram_chat_id == str(chat_id),
                User.id != user.id,
            )
            .first()
        )

        if existing_user:
            print(
                "[Telegram] Telegram chat already belongs to another "
                f"SOC account | existing_user_id={existing_user.id} | "
                f"requested_user_id={user.id}"
            )

            send_message(
                chat_id,
                "❌ This Telegram account is already connected to another SOC Platform account.",
            )
            return

        # ----------------------------------------------------
        # Connect Telegram
        # ----------------------------------------------------

        user.telegram_chat_id = str(chat_id)
        user.telegram_username = telegram_username
        user.telegram_connected = True
        user.telegram_connected_at = datetime.utcnow()

        link_token.used = True

        db.commit()

        print(
            "[Telegram] Account connected successfully | "
            f"user_id={user.id} | "
            f"username={user.username} | "
            f"chat_id={chat_id}"
        )

        send_message(
            chat_id,
            f"✅ Telegram connected successfully.\n\n"
            f"SOC Platform user: {user.username}\n\n"
            f"You can now use this Telegram account to access your "
            f"authorized SOC Platform features.",
        )

    except Exception as exc:
        db.rollback()

        print(
            f"[Telegram] Authentication error: {exc}"
        )

        send_message(
            chat_id,
            "❌ An error occurred while connecting your Telegram account.\n\n"
            "Please try again from the SOC Platform.",
        )

    finally:
        db.close()


# ============================================================
# TELEGRAM COMMAND HANDLER
# ============================================================

def handle_update(update: dict):
    message = update.get("message")

    if not message:
        return

    text = message.get("text")

    if not text:
        return

    chat = message.get("chat")

    if not chat:
        return

    chat_id = chat.get("id")

    if chat_id is None:
        return

    telegram_user = message.get("from") or {}

    telegram_username = telegram_user.get(
        "username"
    )

    # --------------------------------------------------------
    # SAFE incoming-message diagnostic
    # --------------------------------------------------------

    print(
        "[Telegram] Incoming message | "
        f"chat_id={chat_id} | "
        f"text_length={len(text)}"
    )

    # --------------------------------------------------------
    # /start
    # --------------------------------------------------------

    if text.startswith("/start"):

        parts = text.split(maxsplit=1)

        # ----------------------------------------------------
        # Plain /start
        # ----------------------------------------------------

        if len(parts) == 1:
            print(
                "[Telegram] Plain /start received | "
                "No connection parameter supplied"
            )

            send_message(
                chat_id,
                "👋 Welcome to the SOC Security Platform Bot.\n\n"
                "To connect your SOC Platform account, generate a "
                "Telegram connection link from your SOC Platform "
                "dashboard and open it.",
            )
            return

        # ----------------------------------------------------
        # /start <token>
        # ----------------------------------------------------

        token = parts[1].strip()

        if not token:
            print(
                "[Telegram] /start contained an empty token"
            )

            send_message(
                chat_id,
                "❌ Invalid connection token.",
            )
            return

        print(
            "[Telegram] /start contains a connection parameter | "
            f"parameter_length={len(token)}"
        )

        process_start_command(
            chat_id=chat_id,
            telegram_username=telegram_username,
            token=token,
        )

        return

    # --------------------------------------------------------
    # /help
    # --------------------------------------------------------

    if text == "/help":
        send_message(
            chat_id,
            "SOC Security Platform Bot\n\n"
            "/start - Connect your SOC account\n"
            "/help - Show help\n"
            "/status - Check connection",
        )
        return

    # --------------------------------------------------------
    # /status
    # --------------------------------------------------------

    if text == "/status":

        db = SessionLocal()

        try:
            user = (
                db.query(User)
                .filter(
                    User.telegram_chat_id == str(chat_id),
                    User.telegram_connected == True,
                )
                .first()
            )

            if not user:
                send_message(
                    chat_id,
                    "❌ This Telegram account is not connected to a "
                    "SOC Platform account.",
                )
                return

            send_message(
                chat_id,
                f"✅ Telegram account connected.\n\n"
                f"SOC User: {user.username}\n"
                f"Email: {user.email}",
            )

        finally:
            db.close()

        return

    # --------------------------------------------------------
    # UNKNOWN COMMAND
    # --------------------------------------------------------

    send_message(
        chat_id,
        "Unknown command.\n\n"
        "Use /help to see available commands.",
    )


# ============================================================
# TELEGRAM LONG POLLING
# ============================================================

def run_bot():
    print(
        "[Telegram] SOC Telegram Bot starting..."
    )

    offset = 0

    while True:

        try:

            response = httpx.get(
                f"{TELEGRAM_API_URL}/getUpdates",
                params={
                    "offset": offset,
                    "timeout": 30,
                    "allowed_updates": '["message"]',
                },
                timeout=40,
            )

            response.raise_for_status()

            data = response.json()

            if not data.get("ok"):
                print(
                    "[Telegram] API returned an error:",
                    data,
                )

                time.sleep(5)
                continue

            updates = data.get(
                "result",
                [],
            )

            if updates:
                print(
                    f"[Telegram] Received {len(updates)} update(s)"
                )

            for update in updates:

                update_id = update.get(
                    "update_id"
                )

                if update_id is not None:
                    offset = update_id + 1

                handle_update(update)

        except KeyboardInterrupt:

            print(
                "\n[Telegram] Bot stopped."
            )
            break

        except Exception as exc:

            print(
                f"[Telegram] Polling error: {exc}"
            )

            time.sleep(5)


# ============================================================
# START
# ============================================================

if __name__ == "__main__":
    run_bot()