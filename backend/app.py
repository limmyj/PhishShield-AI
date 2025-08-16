import os
import io
import sys
import time
import json
import hashlib
import threading

from flask_cors import CORS
from bs4 import BeautifulSoup
from datetime import datetime
from collections import defaultdict
from flask import Flask, request, jsonify, render_template
from unified_predict import unified_predict, SPAM_KEYWORDS

from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.feature_selection import SelectFromModel
from sklearn.calibration import CalibratedClassifierCV
from sklearn.naive_bayes import GaussianNB, MultinomialNB
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier, StackingClassifier

READY = False

PROFILE_DIR = os.path.join(os.path.expanduser("~"), "PhishShieldData", "profiles")
os.makedirs(PROFILE_DIR, exist_ok=True)

# Log File
LOG_DIR = os.path.join(os.path.expanduser("~"), "PhishShieldData", "logs")
os.makedirs(LOG_DIR, exist_ok=True)

log_filename = f"backend_log_{datetime.now().strftime('%Y-%m-%d')}.txt"
log_path = os.path.join(LOG_DIR, log_filename)

sys.stdout = open(log_path, "a", encoding="utf-8")
sys.stderr = sys.stdout

app = Flask(__name__)
CORS(app)

last_result = {}

if getattr(sys, 'frozen', False):
    BASE_PATH = sys._MEIPASS
else:
    BASE_PATH = os.path.dirname(__file__)

@app.route('/api/check', methods=['POST'])
def check_email():
    global last_result, READY

    if not READY:
        return jsonify({
            "verdict": "initializing",
            "message": "Backend is still initializing. Please wait a few seconds."
        }), 503
    
    try:
        data = request.get_json(force=True, silent=True)
        if not data:
            raise ValueError("Missing JSON payload")

        subject = data.get("subject", "").strip()
        body = data.get("email_text", "").strip()

        if not subject and not body:
            return jsonify({
                "verdict": "insufficient",
                "message": "No content to analyze. Email subject and body are empty."
            })

        print(f"📨 Received email from {data.get('sender', 'unknown')} - subject: {subject or '[no subject]'} - body length: {len(body)}")

        if not body:
            print("⚠️ Email body is empty. Proceeding with subject-only analysis.")
            data["email_text"] = subject 

        result = unified_predict(data)
        last_result = result.copy()

        return jsonify(result)

    except Exception as e:
        print("🔥 Backend error:", e)
        return jsonify({"error": str(e)}), 500

@app.route('/url_details')
def url_details():
    url = request.args.get('url')
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    cached = last_result.get("url_predictions", {}).get(url)

    if not cached:
        for original_url, data in last_result.get("url_predictions", {}).items():
            if data.get("final_url") == url:
                cached = data
                break

    if cached and "original_features" in cached:
        return jsonify({
            "label": cached.get("label", "Unknown"),
            "confidence": cached.get("confidence", 0.0),
            "original_url": cached.get("original_url", url),
            "final_url": cached.get("final_url", url),
            "original_features": cached.get("original_features", {}),
            "resolved_features": cached.get("resolved_features", {}),
            "features": cached.get("resolved_features", {}), 
            "screenshot_base64": cached.get("screenshot_base64"),
            "redirection_mismatch": cached.get("redirection_mismatch", False),
            "resolved_domain": cached.get("resolved_domain", ""),
            "original_domain": cached.get("original_domain", "")
        })

    return jsonify({"error": "Feature details not found"}), 404

@app.route("/details")
def details():
    global last_result
    if not last_result:
        return "⚠️ No data available. Try scanning email from the extension first.", 400

    result = last_result.copy()
    url_predictions = result.get("url_predictions", {})
    grouped_urls = defaultdict(list)
    for url, info in url_predictions.items():
        grouped_urls[info["label"]].append((url, info))

    # Sort table by confidence descending
    for label in grouped_urls:
        grouped_urls[label].sort(key=lambda x: x[1]["confidence"], reverse=True)

    sender = result.get("sender", "")
    user_id = hashlib.md5(sender.lower().encode()).hexdigest()

    profile_path = os.path.join(PROFILE_DIR, f"{user_id}.json")
    if os.path.exists(profile_path):
        with open(profile_path, "r") as f:
            sender_profile = json.load(f)
        result["sender_history"] = sender_profile
    else:
        result["sender_history"] = {"history": []}

    DEBUG = True
    if DEBUG: 
        print("sender_history:", result["sender_history"])
        print("history:", result["sender_history"].get("history", []))

    subject = result.get("subject", "").strip()
    email_text = result.get("email_text", "").strip()

    def clean_text(text):
        return BeautifulSoup(text, "html.parser").get_text().strip().lower()

    subject_clean = clean_text(subject)
    email_text_clean = clean_text(email_text)

    email_body_same_as_subject = (
        email_text and subject and email_text_clean == subject_clean
    )

    return render_template("details.html", result=result, grouped_urls=grouped_urls, email_body_same_as_subject=email_body_same_as_subject)

@app.route('/api/spam_keywords')
def get_keywords():
    return jsonify({"keywords": SPAM_KEYWORDS})

@app.route("/api/sender_history")
def get_sender_history():
    email = request.args.get("email")
    if not email:
        return jsonify({"error": "Missing sender email"}), 400

    user_id = hashlib.md5(email.lower().encode()).hexdigest()

    profile_path = os.path.join(PROFILE_DIR, f"{user_id}.json")

    if not os.path.exists(profile_path):
        return jsonify({"history": []})

    with open(profile_path, "r") as f:
        profile = json.load(f)
        return jsonify({
            "sender": profile.get("sender", email),
            "history": profile.get("history", [])
        })
    
@app.template_filter('timestamp_to_datetime')
def timestamp_to_datetime_filter(ts):
    return datetime.fromtimestamp(ts).strftime("%d %b %Y, %I:%M %p")

def initialize_backend():
    global READY
    print("⚙️ Initializing backend... Please wait.")
    
    time.sleep(5) 

    READY = True
    print("✅ Backend is ready for analysis.")

threading.Thread(target=initialize_backend).start()

if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5000)