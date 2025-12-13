import os
import re
from dotenv import load_dotenv
from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, current_user
)
from flask_bcrypt import Bcrypt
from flask_cors import CORS
import requests

from models import db, User, Conversation, Message

EMAIL_REGEX = re.compile(r".+@.+\..+")

load_dotenv()
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key")
DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY")

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite3"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
CORS(app, supports_credentials=True, origins="*")


@login_manager.unauthorized_handler
def unauthorized():
    return jsonify({"message": "Authentication required"}), 401


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/")
def root():
    if current_user.is_authenticated:
        return redirect(url_for("chat_page"))
    return redirect(url_for("login_page"))


@app.route("/login")
def login_page():
    return render_template("login.html")


@app.route("/chat")
def chat_page():
    return render_template("chat.html")


# زر "Continue without login" يوجّه مباشرة لصفحة الشات كضيف
@app.route("/guest-login")
def guest_login():
    session["is_guest"] = True
    return redirect(url_for("chat_page"))

def generate_chat_title(question: str) -> str:
    """
    توليد عنوان للمحادثة من أول رسالة ذات معنى:
    - يشيل عبارات الترحيب في البداية
    - يوقف عند أول ؟ أو . أو !
    - يقص العنوان إذا كان طويل جدًا
    """
    if not question:
        return "New Chat"

    text = question.strip()

    greetings = [
        "hi", "hello", "hey", "yo",
        "مرحبا", "مرحبا!", "مرحبا،",
        "هلا", "هلا والله",
        "السلام عليكم", "صباح الخير", "مساء الخير"
    ]

    lower = text.lower().strip()
    for g in greetings:
        g_lower = g.lower()
        if lower.startswith(g_lower):
            lower = lower[len(g_lower):].lstrip(" ،,!.؟")
            break

    if not lower:
        lower = text

    cut_chars = [".", "?", "!", "؟", "،", "؛"]
    first_sentence = lower
    for ch in cut_chars:
        if ch in first_sentence:
            first_sentence = first_sentence.split(ch)[0]
            break

    first_sentence = first_sentence.strip()
    if not first_sentence:
        first_sentence = lower.strip()

    max_len = 40
    if len(first_sentence) > max_len:
        first_sentence = first_sentence[:max_len].rstrip() + "..."

    return first_sentence or "New Chat"


@app.route("/api/whoami")
def whoami():
    """
    ترجع بيانات المستخدم الحالي:
    - إذا مسجّل دخول: is_guest = False + username/email/created_at
    - إذا ضيف: is_guest = True + Guest
    """
    if current_user.is_authenticated:
        return jsonify({
            "is_guest": False,
            "username": current_user.username,
            "email": current_user.email,
            "created_at": current_user.created_at.isoformat()
            if hasattr(current_user, "created_at") and current_user.created_at
            else None,
        })
    else:
        return jsonify({
            "is_guest": True,
            "username": "Guest",
            "email": None,
            "created_at": None,
        })


@app.route("/ask", methods=["POST"])
def ask():
    """
    نقطة إرسال السؤال للذكاء الاصطناعي.

    - لو المستخدم ضيف (غير مسجّل):
        * لا نستخدم chatId
        * لا نحفظ أي شيء في قاعدة البيانات
        * نرسل فقط system prompt + رسالة المستخدم لـ DeepSeek

    - لو المستخدم مسجّل:
        * نحتاج chatId
        * نحمّل المحادثة من قاعدة البيانات
        * نحفظ رسالة المستخدم + رد الـ AI
        * نرجع عنوان الشات عند أول رسالة ذات معنى
    """
    data = request.get_json() or {}
    question = (data.get("question") or "").strip()
    chat_id = data.get("chatId")

    if not question:
        return jsonify({"error": "Question is required"}), 400

    if not DEEPSEEK_API_KEY:
        return jsonify({"error": "DEEPSEEK_API_KEY is missing in .env"}), 500

    # -------- ضيف (Guest) --------
    if not current_user.is_authenticated:
        ds_messages = []

        ds_messages.append({
            "role": "system",
            "content": (
                "You are an expert barista and coffee educator. "
                "Respond like a friendly human barista talking to a customer at the counter. "
                "For each answer, keep the length medium: not very long and not very short "
                "(about 2–4 short paragraphs). "
                "Start with a clear, direct answer in 1–2 sentences, then give a short explanation "
                "in a human, story-like way when helpful (for example, describing how the coffee would taste "
                "or what the barista would do in real life). "
                "Be accurate and practical, focus on what the user should actually do. "
                "Use simple language, avoid heavy technical jargon, and only use short bullet lists "
                "(3–5 items) when they really make things clearer."
            )
        })

        ds_messages.append({
            "role": "user",
            "content": question
        })

        try:
            url = "https://api.deepseek.com/v1/chat/completions"
            headers = {
                "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
                "Content-Type": "application/json"
            }
            payload = {
                "model": "deepseek-chat",
                "messages": ds_messages,
                "temperature": 0.7,
            }

            resp = requests.post(url, json=payload, headers=headers, timeout=60)
            data = resp.json()

            if resp.status_code != 200:
                msg = data.get("error", {}).get("message", "Unknown DeepSeek error")
                print("DeepSeek error (guest):", resp.status_code, data)
                return jsonify({"error": f"DeepSeek API error: {msg}"}), 500

            ai_answer = data["choices"][0]["message"]["content"]
        except Exception as e:
            print("DeepSeek exception (guest):", e)
            return jsonify({"error": f"Failed to call DeepSeek: {e}"}), 500

        # نرجع فقط رسالة الـ AI بدون تخزين
        return jsonify({
            "ai_message": {
                "sender": "assistant",
                "text": ai_answer.strip()
            },
            "title": None
        })

    # -------- مستخدم مسجّل (Logged in) --------

    if not chat_id:
        return jsonify({"error": "Chat ID is required"}), 400

    # تأكد أن المحادثة تخص هذا المستخدم
    conversation = Conversation.query.filter_by(
        id=chat_id, user_id=current_user.id
    ).first()

    if not conversation:
        return jsonify({"error": "Conversation not found"}), 404

    # أول رسالة ذات معنى في هذا الشات؟
    is_first_message = len(conversation.messages) == 0
    if is_first_message:
        conversation.title = generate_chat_title(question)
        db.session.commit()

    # احفظ رسالة المستخدم
    user_msg = Message(
        sender="user",
        text=question,
        conversation_id=chat_id
    )
    db.session.add(user_msg)
    db.session.commit()

    # حمّل الهستوري كامل
    history = Message.query.filter_by(
        conversation_id=chat_id
    ).order_by(Message.timestamp.asc()).all()

    ds_messages = []

    ds_messages.append({
        "role": "system",
        "content": (
            "You are an expert barista and coffee educator. "
            "Respond like a friendly human barista talking to a customer at the counter. "
            "For each answer, keep the length medium: not very long and not very short "
            "(about 2–4 short paragraphs). "
            "Start with a clear, direct answer in 1–2 sentences, then give a short explanation "
            "in a human, story-like way when helpful (for example, describing how the coffee would taste "
            "or what the barista would do in real life). "
            "Be accurate and practical, focus on what the user should actually do. "
            "Use simple language, avoid heavy technical jargon, and only use short bullet lists "
            "(3–5 items) when they really make things clearer."
        )
    })

    for m in history:
        role = "user" if m.sender == "user" else "assistant"
        ds_messages.append({
            "role": role,
            "content": m.text
        })

    try:
        url = "https://api.deepseek.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": "deepseek-chat",
            "messages": ds_messages,
            "temperature": 0.7,
        }

        resp = requests.post(url, json=payload, headers=headers, timeout=60)
        data = resp.json()

        if resp.status_code != 200:
            msg = data.get("error", {}).get("message", "Unknown DeepSeek error")
            print("DeepSeek error:", resp.status_code, data)
            return jsonify({"error": f"DeepSeek API error: {msg}"}), 500

        ai_answer = data["choices"][0]["message"]["content"]
    except Exception as e:
        print("DeepSeek exception:", e)
        return jsonify({"error": f"Failed to call DeepSeek: {e}"}), 500

    # احفظ رد الـ AI
    ai_msg = Message(
        sender="assistant",
        text=ai_answer.strip(),
        conversation_id=chat_id
    )
    db.session.add(ai_msg)
    db.session.commit()

    return jsonify({
        "user_message": user_msg.to_dict(),
        "ai_message": ai_msg.to_dict(),
        "title": conversation.title if is_first_message else None
    })


# ---------- AUTH ROUTES ----------

@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json() or {}

    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    password = (data.get("password") or "").strip()

    if not username or not email or not password:
        return jsonify({"message": "All fields are required"}), 400

    if len(username) < 3 or len(username) > 30:
        return jsonify({"message": "Username must be between 3 and 30 characters."}), 400

    if not EMAIL_REGEX.match(email):
        return jsonify({"message": "Please enter a valid email address."}), 400

    if len(password) < 6:
        return jsonify({"message": "Password must be at least 6 characters long."}), 400

    existing_user = User.query.filter(
        (User.email == email) | (User.username == username)
    ).first()
    if existing_user:
        return jsonify({"message": "User with this email or username already exists."}), 409

    hashed = bcrypt.generate_password_hash(password).decode("utf-8")
    user = User(username=username, email=email, password_hash=hashed)
    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201


@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip()
    password = (data.get("password") or "").strip()

    user = User.query.filter_by(email=email).first()
    if not user or not bcrypt.check_password_hash(user.password_hash, password):
        return jsonify({"message": "Invalid credentials"}), 401

    login_user(user, remember=True)
    return jsonify({
        "message": "Logged in successfully",
        "user": {
            "username": user.username,
            "email": user.email
        }
    }), 200


@app.route("/api/auth/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logged out successfully"}), 200


@app.route("/api/auth/me", methods=["GET"])
@login_required
def get_me():
    return jsonify({
        "username": current_user.username,
        "email": current_user.email
    }), 200


# ---------- CHATS API (مسجّلين فقط) ----------

@app.route("/api/chats", methods=["GET"])
@login_required
def get_chats():
    convos = Conversation.query.filter_by(
        user_id=current_user.id
    ).order_by(Conversation.id.desc()).all()

    return jsonify([
        {"id": c.id, "title": c.title}
        for c in convos
    ])


@app.route("/api/chats", methods=["POST"])
@login_required
def create_chat():
    convo = Conversation(user_id=current_user.id)
    db.session.add(convo)
    db.session.commit()
    return jsonify({"id": convo.id, "title": convo.title}), 201


@app.route("/api/chats/<int:chat_id>/messages", methods=["GET"])
@login_required
def get_messages(chat_id):
    convo = Conversation.query.filter_by(
        id=chat_id, user_id=current_user.id
    ).first()
    if not convo:
        return jsonify({"error": "Chat not found"}), 404

    msgs = Message.query.filter_by(
        conversation_id=chat_id
    ).order_by(Message.timestamp.asc()).all()

    return jsonify([m.to_dict() for m in msgs])


@app.route("/api/chats/<int:chat_id>", methods=["DELETE"])
@login_required
def delete_chat(chat_id):
    convo = Conversation.query.filter_by(
        id=chat_id, user_id=current_user.id
    ).first()
    if not convo:
        return jsonify({"error": "Chat not found"}), 404

    db.session.delete(convo)
    db.session.commit()
    return jsonify({"message": "Chat deleted successfully"}), 200


@app.route("/api/chats/<int:chat_id>", methods=["PUT"])
@login_required
def rename_chat(chat_id):
    data = request.get_json() or {}
    new_title = (data.get("title") or "").strip()

    if not new_title:
        return jsonify({"error": "New title is required"}), 400

    convo = Conversation.query.filter_by(
        id=chat_id, user_id=current_user.id
    ).first()
    if not convo:
        return jsonify({"error": "Chat not found"}), 404

    convo.title = new_title
    db.session.commit()
    return jsonify({"message": "Chat renamed successfully"}), 200


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)
