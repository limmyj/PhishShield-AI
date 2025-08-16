import os
import time
import json
import hashlib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

BASE_DIR = os.path.join(os.path.expanduser("~"), "PhishShieldData")
PROFILE_DIR = os.path.join(BASE_DIR, "profiles")
os.makedirs(PROFILE_DIR, exist_ok=True)

def generate_user_hash(email_sender):
    return hashlib.md5(email_sender.lower().encode()).hexdigest()

def save_profiles(sender, email_text, subject="Unknown Subject", verdict="Unknown", timestamp=None):
    user_id = generate_user_hash(sender)
    profile_path = os.path.join(PROFILE_DIR, f"{user_id}.json")

    if os.path.exists(profile_path):
        with open(profile_path, 'r') as f:
            profile = json.load(f)
        history = profile.get("history", [])
    else:
        history = []

    current_time = timestamp if timestamp else time.time()

    for entry in history:
        if entry["subject"] == subject and abs(entry["timestamp"] - current_time) < 60:
            print("⏩ Skipping duplicate profile entry (same subject and time)")
            return

    history.append({
        "timestamp": current_time,
        "subject": subject,
        "verdict": verdict
    })
    history = history[-10:]

    tfidf = TfidfVectorizer(max_features=500)
    vector = tfidf.fit_transform([email_text])

    profile = {
        "sender": sender,
        "tfidf_features": tfidf.get_feature_names_out().tolist(),
        "vector": vector.toarray()[0].tolist(),
        "history": history
    }

    print(f"[SAVE] Profile saved for: {sender}, Total history: {len(profile['history'])}")

    with open(profile_path, 'w') as f:
        json.dump(profile, f, indent=2)

    print(f"Profile updated for sender: {sender}")

def load_profiles(sender, new_email_text):
    user_id = generate_user_hash(sender)
    profile_path = os.path.join(PROFILE_DIR, f"{user_id}.json")

    if not os.path.exists(profile_path):
        return None, 0.0  

    with open(profile_path, 'r') as f:
        profile = json.load(f)

    tfidf = TfidfVectorizer(vocabulary=profile["tfidf_features"])
    old_vector = profile["vector"]
    new_vector = tfidf.fit_transform([new_email_text]).toarray()[0]

    similarity = cosine_similarity([old_vector], [new_vector])[0][0]
    return profile, similarity