from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from sqlalchemy.sql import func


db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    conversations = db.relationship(
        'Conversation', backref='user', lazy=True, cascade="all, delete-orphan"
    )

class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False, default="New Chat")
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    messages = db.relationship(
        'Message', backref='conversation', lazy=True, cascade="all, delete-orphan"
    )

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(20), nullable=False)  # 'user' or 'assistant'
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime(timezone=True), server_default=func.now())
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversation.id'), nullable=False)

    def to_dict(self):
        return {
            "sender": self.sender,
            "text": self.text,
            "time": self.timestamp.strftime('%I:%M %p')
        }
    

