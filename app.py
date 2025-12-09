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
    # متاحة للضيف وللمستخدم المسجّل
    return render_template("chat.html")


def generate_chat_title(question: str) -> str:
    """
    توليد عنوان مختصر وذكي من أول سؤال:
    - يتجاهل عبارات الترحيب (hi, hello, مرحبا، السلام عليكم...)
    - يحاول يختار الكلمات المهمة فقط (يتجاهل how, what, is, the... إلخ)
    - يطلع عنوان قصير (٣–٤ كلمات) مثل: "V60 brewing guide"
    """
    if not question:
        return "New Chat"

    text = question.strip()

    # 1) إزالة عبارات الترحيب من البداية
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
            # قصّ التحية من البداية
            lower = lower[len(g_lower):].lstrip(" ،,!.؟")
            break

    # لو بعد إزالة التحية صار فاضي، نرجع للنص الأصلي
    base = lower if lower else text

    # 2) نأخذ فقط أول جملة تقريبًا
    cut_chars = [".", "?", "!", "؟", "،", "؛"]
    for ch in cut_chars:
        if ch in base:
            base = base.split(ch)[0]
            break

    base = base.strip()
    if not base:
        base = text.strip()

    # 3) نكسر الكلمات ونشيل الـ stopwords
    # نستخدم النسخة الأصلية للكلمات علشان نحافظ على "V60" و Capitalization
    original_words = text.strip().split()
    lower_words = [w.lower() for w in original_words]

    stopwords = {
        "how", "what", "when", "where", "why", "who",
        "is", "are", "was", "were", "do", "does", "did",
        "the", "a", "an", "to", "for", "of", "on", "in", "about",
        "can", "could", "would", "should",
        "please", "tell", "me",
        # عربي
        "هل", "ما", "ماذا", "كيف", "عن", "من", "الى", "في", "على", "لو", "اذا"
    }

    keywords = []
    for orig, low in zip(original_words, lower_words):
        # نتجاهل رموز بسيطة
        if not low or all(ch in ".,!?،؛:()" for ch in low):
            continue
        if low in stopwords:
            continue
        keywords.append(orig)

    # لو ما قدر يطلع كلمات مهمة، نستخدم الجملة الأساسية
    if not keywords:
        cleaned = base
    else:
        # نختار أول 3–4 كلمات مهمة
        cleaned = " ".join(keywords[:4])

    # 4) تقصير لو العنوان طويل جدًا
    max_len = 40
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len].rstrip() + "..."

    return cleaned or "New Chat"



@app.route("/api/whoami")
def whoami():
    if current_user.is_authenticated:
        return jsonify({
            "is_guest": False,
            "username": current_user.username,
            "email": current_user.email,
            "created_at": current_user.created_at.isoformat() if hasattr(current_user, "created_at") else None,
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
    - لو المستخدم مسجّل:
        يعتمد على chatId، يخزن في DB، يستخدم history، ويحدّث عنوان الشات
        أول ما تجي رسالة "مفيدة" (ولو كانت الرسالة الثانية بعد مرحبا).
    - لو المستخدم ضيف:
        يتجاهل chatId، ما يخزن في DB، يرد فقط من DeepSeek.
    """
    data = request.get_json() or {}
    question = (data.get("question") or "").strip()
    chat_id = data.get("chatId")

    if not question:
        return jsonify({"error": "Question is required"}), 400

    if not DEEPSEEK_API_KEY:
        return jsonify({"error": "DEEPSEEK_API_KEY is missing in .env"}), 500

    is_guest = not current_user.is_authenticated

    # نجهز الرسائل لـ DeepSeek
    ds_messages = []

    # system prompt للباريستا
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

    conversation = None
    title = None
    user_msg = None

    # ============ حالة الضيف ============
    if is_guest:
        # ما في DB ولا chatId
        ds_messages.append({
            "role": "user",
            "content": question
        })

    # ============ حالة المستخدم المسجّل ============
    else:
        if not chat_id:
            return jsonify({"error": "Chat ID is required"}), 400

        conversation = Conversation.query.filter_by(
            id=chat_id, user_id=current_user.id
        ).first()
        if not conversation:
            return jsonify({"error": "Conversation not found"}), 404

        # نشوف هل العنوان الحالي تافه ونسمح بتحديثه
        default_titles = {
            "", "new chat", "chat", "hi", "hello",
            "مرحبا", "سلام", "coffee chat"
        }
        current_title = (conversation.title or "").strip()
        should_update_title = (
            not current_title or current_title.lower() in default_titles
        )

        # نخزن رسالة المستخدم
        user_msg = Message(
            sender="user",
            text=question,
            conversation_id=chat_id
        )
        db.session.add(user_msg)
        db.session.flush()  # يحجز id بدون commit نهائي

        # نبني الـ history (من الرسائل القديمة فقط)
        history = Message.query.filter_by(
            conversation_id=chat_id
        ).order_by(Message.timestamp.asc()).all()

        for m in history:
            role = "user" if m.sender == "user" else "assistant"
            ds_messages.append({
                "role": role,
                "content": m.text
            })

        # نضيف رسالة المستخدم الحالية للـ API
        ds_messages.append({
            "role": "user",
            "content": question
        })

        # لو العنوان الحالي تافه، نحاول نولّد عنوان جديد من هذا السؤال
        if should_update_title:
            new_title = generate_chat_title(question)
            if new_title and new_title != "New Chat":
                conversation.title = new_title
                title = new_title
        # لو ما حدثناه، نرجع None عشان الواجهة ما تغيّر الاسم القديم

    # ============ نداء DeepSeek ============
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

    # ============ تخزين رد الـ AI للمستخدم المسجّل فقط ============
    if not is_guest and conversation is not None and user_msg is not None:
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
            "title": title  # لو None الواجهة ما تغيّر الاسم
        })

    # ============ رد الضيف (بدون حفظ) ============
    return jsonify({
        "ai_message": {"text": ai_answer.strip()},
        "title": None
    })


    # ============ رد الضيف (بدون حفظ) ============
    return jsonify({
        "ai_message": {"text": ai_answer.strip()},
        "title": None
    })


@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json() or {}

    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    password = (data.get("password") or "").strip()

    print("REGISTER TRY:", repr(username), repr(email))

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
