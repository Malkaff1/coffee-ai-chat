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
# ------------------- إعداد .env -------------------

load_dotenv()
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key")
DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY")  # حط المفتاح في .env




# ------------------- إعداد Flask -------------------

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

# ===================================================
#                 صفحات HTML
# ===================================================

@app.route("/")
def root():
    if current_user.is_authenticated:
        return redirect(url_for("chat_page"))
    return redirect(url_for("login_page"))

@app.route("/login")
def login_page():
    return render_template("login.html")

@app.route("/chat")
@login_required
def chat_page():
    return render_template("chat.html")



# ---------- Chat title helper ----------

def generate_chat_title(question: str) -> str:
    """
    يحاول يطلع عنوان واضح من أول رسالة:
    - يشيل عبارات الترحيب في البداية
    - يكتفي بأول جملة لو فيها ؟ أو .
    - يقص العنوان لطول مناسب
    """
    if not question:
        return "New Chat"

    text = question.strip()

    # 1) شيل التحيات الشائعة في البداية (عربي + إنجليزي)
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
            # قص التحية من البداية
            lower = lower[len(g_lower):].lstrip(" ،,!.؟")
            break

    # لو بعد إزالة التحية صار فاضي، نرجع النص الأصلي
    if not lower:
        lower = text

    # 2) خذ أول جملة بس (إلى أول ؟ أو . أو ! أو ،)
    cut_chars = [".", "?", "!", "؟", "،", "؛"]
    first_sentence = lower
    for ch in cut_chars:
        if ch in first_sentence:
            first_sentence = first_sentence.split(ch)[0]
            break

    first_sentence = first_sentence.strip()

    if not first_sentence:
        first_sentence = lower.strip()

    # 3) حد أقصى للطول (مثلاً 40 حرف)
    max_len = 40
    if len(first_sentence) > max_len:
        first_sentence = first_sentence[:max_len].rstrip() + "..."

    # 4) لو كل شيء فشل
    return first_sentence or "New Chat"


# ===================================================
#               /ask – DeepSeek API
# ===================================================

@app.route("/ask", methods=["POST"])
@login_required
def ask():
    """
    يستقبل سؤال من الفرونت، يحفظه في الداتابيز،
    يرسل الهيستوري كامل لـ DeepSeek، يرجع رد الـ AI،
    ويحفظه أيضاً في الداتابيز.
    """
    data = request.get_json()
    question = data.get("question")
    chat_id = data.get("chatId")

    if not question:
        return jsonify({"error": "Question is required"}), 400
    if not chat_id:
        return jsonify({"error": "Chat ID is required"}), 400

    if not DEEPSEEK_API_KEY:
        return jsonify({"error": "DEEPSEEK_API_KEY is missing in .env"}), 500

    # تأكيد أن المحادثة للمستخدم الحالي
    conversation = Conversation.query.filter_by(
        id=chat_id, user_id=current_user.id
    ).first()
    if not conversation:
        return jsonify({"error": "Conversation not found"}), 404

    # أول رسالة → نولد عنوان أوضح
    is_first_message = len(conversation.messages) == 0
    if is_first_message:
        conversation.title = generate_chat_title(question)


    # نحفظ رسالة المستخدم
    user_msg = Message(
        sender="user",
        text=question,
        conversation_id=chat_id
    )
    db.session.add(user_msg)
    db.session.commit()

    # نجيب الهيستوري كامل لهذه المحادثة من الداتابيز
    history = Message.query.filter_by(
        conversation_id=chat_id
    ).order_by(Message.timestamp.asc()).all()

    # نحوله للفورمات اللي تحبه DeepSeek
    ds_messages = []

    # System prompt يخلي الموديل متخصّص بالقهوة (تقدر تعدله)
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

    # نرسل الطلب لـ DeepSeek
    try:
        url = "https://api.deepseek.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": "deepseek-chat",   # لو غيرت الموديل من لوحة ديبسيك عدل الاسم هنا
            "messages": ds_messages,
            "temperature": 0.7,
        }

        resp = requests.post(url, json=payload, headers=headers, timeout=60)
        data = resp.json()

        # لو فيه خطأ من DeepSeek نفسه (مثلاً Insufficient Balance)
        if resp.status_code != 200:
            msg = data.get("error", {}).get("message", "Unknown DeepSeek error")
            print("DeepSeek error:", resp.status_code, data)
            return jsonify({"error": f"DeepSeek API error: {msg}"}), 500

        ai_answer = data["choices"][0]["message"]["content"]

    except Exception as e:
        print("DeepSeek exception:", e)
        return jsonify({"error": f"Failed to call DeepSeek: {e}"}), 500

    # نحفظ رد الـ AI في الداتابيز
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

# ===================================================
#                 AUTH API
# ===================================================

@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json() or {}

    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    password = (data.get("password") or "").strip()

    # فقط للتأكد في اللوق
    print("REGISTER TRY:", repr(username), repr(email))

    # 1) الحقول الأساسية
    if not username or not email or not password:
        return jsonify({"message": "All fields are required"}), 400

    # 2) طول اليوزرنيم منطقي
    if len(username) < 3 or len(username) > 30:
        return jsonify({"message": "Username must be between 3 and 30 characters."}), 400

    # 3) شكل الإيميل (بسيط جداً)
    if not EMAIL_REGEX.match(email):
        return jsonify({"message": "Please enter a valid email address."}), 400

    # 4) طول الباسورد
    if len(password) < 6:
        return jsonify({"message": "Password must be at least 6 characters long."}), 400

    # 5) تأكد ما فيه مستخدم بنفس الإيميل أو اليوزرنيم
    existing_user = User.query.filter(
        (User.email == email) | (User.username == username)
    ).first()

    if existing_user:
        return jsonify({"message": "User with this email or username already exists."}), 409

    # 6) إنشاء المستخدم
    hashed = bcrypt.generate_password_hash(password).decode("utf-8")
    user = User(username=username, email=email, password_hash=hashed)
    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201



@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

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

# ===================================================
#            Chat list + messages API
# ===================================================

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
    data = request.get_json()
    new_title = data.get("title")

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

# ===================================================
#                  تشغيل التطبيق
# ===================================================

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)
