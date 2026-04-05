from flask import Flask, request, jsonify, session
from flask_cors import CORS
import joblib
import re
import os
import sqlite3
import hashlib
import secrets

# ----------------------------
# Config
# ----------------------------
MODEL_FILE = os.environ.get("MODEL_FILE", "tamil_phishing_lr_tfidf.joblib")
THRESHOLD = float(os.environ.get("THRESHOLD", "0.5"))
DATABASE = "users.db"
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(16))

URL_RE = re.compile(r"(https?://\S+|www\.\S+)", re.IGNORECASE)

def clean_text(text: str) -> str:
    text = str(text)
    text = URL_RE.sub("<URL>", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text

# ----------------------------
# Database setup
# ----------------------------
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()
    print("✅ Database ready: users.db")

def hash_password(password: str) -> str:
    salt = "taroshield_salt_2024"
    return hashlib.sha256((password + salt).encode()).hexdigest()

# ----------------------------
# Load model once at startup
# ----------------------------
model = joblib.load(MODEL_FILE)
print(f"✅ Model loaded: {MODEL_FILE}")

app = Flask(__name__)
app.secret_key = SECRET_KEY
CORS(app, supports_credentials=True)

init_db()

# ----------------------------
# Auth Routes
# ----------------------------

@app.route("/signup", methods=["POST", "OPTIONS"])
def signup():
    if request.method == "OPTIONS":
        return jsonify({}), 200

    data = request.get_json(silent=True) or {}
    full_name = data.get("full_name", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "").strip()

    if not full_name or not email or not password:
        return jsonify({"success": False, "message": "All fields are required."}), 400
    if len(password) < 6:
        return jsonify({"success": False, "message": "Password must be at least 6 characters."}), 400
    if "@" not in email:
        return jsonify({"success": False, "message": "Invalid email address."}), 400

    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO users (full_name, email, password) VALUES (?, ?, ?)",
            (full_name, email, hash_password(password))
        )
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": "Account created! You can now log in."}), 201
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "message": "Email already registered. Please log in."}), 409


@app.route("/login", methods=["POST", "OPTIONS"])
def login():
    if request.method == "OPTIONS":
        return jsonify({}), 200

    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "").strip()

    if not email or not password:
        return jsonify({"success": False, "message": "Email and password are required."}), 400

    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE email = ? AND password = ?",
        (email, hash_password(password))
    ).fetchone()
    conn.close()

    if user:
        session["user_id"] = user["id"]
        session["user_name"] = user["full_name"]
        return jsonify({
            "success": True,
            "message": f"Welcome back, {user['full_name']}!",
            "full_name": user["full_name"],
            "email": user["email"]
        })
    else:
        return jsonify({"success": False, "message": "Invalid email or password."}), 401


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"success": True, "message": "Logged out."})


@app.route("/me", methods=["GET"])
def me():
    if "user_id" in session:
        return jsonify({"logged_in": True, "full_name": session.get("user_name")})
    return jsonify({"logged_in": False})


# ----------------------------
# Health & Predict Routes
# ----------------------------
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "model_file": MODEL_FILE})


@app.route("/predict", methods=["POST", "OPTIONS"])
def predict():
    if request.method == "OPTIONS":
        return jsonify({}), 200

    data = request.get_json(silent=True) or {}
    text = data.get("text", "")

    if not text or not str(text).strip():
        return jsonify({"error": "Missing 'text'"}), 400

    x = [clean_text(text)]

    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(x)[0][1]
        risk = float(proba)
        label = "phishing" if risk >= THRESHOLD else "legitimate"
    else:
        pred = int(model.predict(x)[0])
        risk = None
        label = "phishing" if pred == 1 else "legitimate"

    return jsonify({"label": label, "risk": risk, "threshold": THRESHOLD})


@app.route("/predict-batch", methods=["POST", "OPTIONS"])
def predict_batch():
    if request.method == "OPTIONS":
        return jsonify({}), 200

    data = request.get_json(silent=True) or {}
    texts = data.get("texts", [])

    if not isinstance(texts, list) or len(texts) == 0:
        return jsonify({"error": "Provide 'texts' as a non-empty list"}), 400

    X = [clean_text(t) for t in texts]
    results = []

    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(X)[:, 1]
        for original_text, p in zip(texts, probs):
            p = float(p)
            results.append({
                "text": original_text,
                "label": "phishing" if p >= THRESHOLD else "legitimate",
                "risk": p
            })
    else:
        preds = model.predict(X)
        for original_text, pred in zip(texts, preds):
            results.append({
                "text": original_text,
                "label": "phishing" if int(pred) == 1 else "legitimate",
                "risk": None
            })

    return jsonify({"results": results, "threshold": THRESHOLD})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
