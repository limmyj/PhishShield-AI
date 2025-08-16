import re 
import os
import sys
import time
import json
import joblib
import numpy as np
import pandas as pd

from datetime import datetime
from bs4 import BeautifulSoup
from langdetect import detect
from feature import extract_features, resolve_final_url, get_screenshot_base64
from behavior_profile import save_profiles, load_profiles
from utils.url_history import load_url_analysis, save_url_analysis

if getattr(sys, 'frozen', False):
    BASE_PATH = sys._MEIPASS
else:
    BASE_PATH = os.path.dirname(__file__)

email_model = joblib.load(os.path.join(BASE_PATH, "newEmailmodels", "mlp_classifier_model.pkl"))
tfidf = joblib.load(os.path.join(BASE_PATH, "newEmailmodels", "tfidf_vectorizer.pkl"))
url_model1 = joblib.load(os.path.join(BASE_PATH, "newURL3.0", "random_forest_model.pkl"))
url_model2 = joblib.load(os.path.join(BASE_PATH, "newURL3.0", "calibrated_random_forest_model.pkl"))
le = joblib.load(os.path.join(BASE_PATH, "newURL3.0", "label_encoder.pkl"))
scaler = joblib.load(os.path.join(BASE_PATH, "newURL3.0", "scaler.pkl"))
feature_order = joblib.load(os.path.join(BASE_PATH, "newURL3.0", "feature_order.pkl"))

ALEXA_TOP_DOMAINS = set()

def load_alexa_domains(csv_path):
    global ALEXA_TOP_DOMAINS
    try:
        df = pd.read_csv(csv_path, header=None, names=['rank', 'domain'])
        ALEXA_TOP_DOMAINS = set(df['domain'].str.strip().str.lower())
        print(f"Loaded {len(ALEXA_TOP_DOMAINS):,} trusted Alexa domains.")
    except Exception as e:
        print(f"Failed to load Alexa CSV: {e}")

load_alexa_domains(os.path.join(BASE_PATH, "Datasets", "alexa-top-1m.csv"))

def load_spam_keywords(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        return [line.strip().lower() for line in f if line.strip()]

SPAM_KEYWORDS = load_spam_keywords(os.path.join(BASE_PATH, "Datasets", "spam_keywords.txt"))

SPAM_KEYWORD_CATEGORIES = {
    "Credential Theft": [
        "login", "sign in", "verify", "password", "credentials", "passcode",
        "security code", "pin", "confirm identity", "reset now",
        "update information", "secure your account", "update credentials",
        "account verification", "validate account", "login attempt",
        "unauthorized access", "verify your account", "authentication required",
        "password expired", "security alert"
    ],
    "Urgency or Threats": [
        "urgent", "act now", "immediately", "within 24 hours", "risk",
        "suspend", "warning", "failure to", "limited time", "final notice",
        "action required", "respond immediately", "time sensitive",
        "security notice", "account disabled", "temporary hold",
        "unauthorized login", "account compromised", "session expired",
        "take action now", "your attention is needed", "expire", "expired"
    ],
    "Financial Terms": [
        "bank", "account", "payment", "invoice", "transaction",
        "billing", "balance", "card", "credit card", "debit card",
        "funds", "pay now", "make payment", "billing issue", 
        "payment failed", "payment declined", "payment overdue",
        "monthly statement", "unauthorized transaction", 
        "refund available", "claim your refund"
    ],
    "Reward or Prizes": [
        "win", "free", "congratulations", "reward", "cash", "voucher",
        "lucky draw", "promo", "exclusive offer", "you've been selected",
        "get your prize", "claim reward", "you are a winner", 
        "redeem now", "bonus", "cash prize", "gift card", 
        "mystery reward", "claim your prize"
    ],
    "Phishing Phrases": [
        "click here", "verify now", "login below", "click below",
        "open attachment", "view document", "download report",
        "check the link", "see details", "access your invoice", 
        "verify your info", "confirm now", "your mailbox is full", 
        "re-login", "complete the form"
    ],
    "Email Service Alerts": [
        "mailbox full", "storage exceeded", "email quota",
        "delivery failed", "email deactivated", "inbox alert",
        "revalidate email", "reactivate account", "update mailbox"
    ]
}

SPAM_KEYWORD_MAP = {}
for category, words in SPAM_KEYWORD_CATEGORIES.items():
    for word in words:
        SPAM_KEYWORD_MAP[word.lower()] = category

def has_spam_keywords(text):
    text_lower = text.lower()
    return int(any(keyword in text_lower for keyword in SPAM_KEYWORDS))

def count_spam_keywords(text):
    text_lower = text.lower()
    return sum(1 for keyword in SPAM_KEYWORDS if keyword in text_lower)

def clean_url(url):
    return url.rstrip(').,]')

def extract_urls(text):
    urls = set()

    raw_urls = re.findall(r"https?://[^\s\"'>]+", text)
    for u in raw_urls:
        u = clean_url(u)
        if "google.com/url?q=" in u:
            match = re.search(r'q=(https?://[^&]+)', u)
            if match:
                real_url = clean_url(match.group(1))
                urls.add(real_url)
        else:
            urls.add(u)

    try:
        soup = BeautifulSoup(text, 'lxml')
        for tag in soup.find_all('a', href=True):
            href = tag['href']
            if "google.com/url?q=" in href:
                match = re.search(r'q=(https?://[^&]+)', href)
                if match:
                    real_url = clean_url(match.group(1))
                    urls.add(real_url)
            else:
                urls.add(href)

        for tag in soup.find_all(onclick=True):
            if "window.location.href" in tag['onclick']:
                raw = tag['onclick']
                match = re.search(r"'(https?://[^']+)'", raw)
                if match:
                    url = clean_url(match.group(1))
                    urls.add(url)
    except Exception as e:
        print(f"[Soup URL parse error] {e}")

    return list(urls)

def is_trusted_domain(domain):
    parts = domain.lower().split('.')
    if len(parts) >= 2:
        root = ".".join(parts[-2:])
        return domain in ALEXA_TOP_DOMAINS or root in ALEXA_TOP_DOMAINS
    return domain in ALEXA_TOP_DOMAINS

def label_logic(proba, features):
    diff = abs(proba[0] - proba[1])
    phishing_score = proba[1]

    domain = features.get("URL Domain", "").lower().strip()
    is_registered = features.get("Is Registered Company Domain", 0)
    has_login_keyword = features.get("Has Suspicious Keywords", 0)
    redirect_mismatch = features.get("Redirection Mismatch", False)
    depth = features.get("URL Depth", 0)
    entropy = features.get("URL Entropy", 0.0)

    if is_trusted_domain(domain) and is_registered == 1 and not redirect_mismatch and features.get("URL Depth", 0) <= 3:
        if depth <= 3 and entropy <= 4.5:
            print("Trusted Alexa domain override applied.")
            phishing_score = min(phishing_score, 0.30)
            proba[1] = phishing_score
            proba[0] = 1 - phishing_score
            diff = abs(proba[0] - proba[1])

    if is_registered == 1 and has_login_keyword == 1:
        print("🔧 Logic override: registered domain with login keyword.")
        phishing_score = min(phishing_score, 0.45)
        proba[1] = phishing_score
        proba[0] = 1 - phishing_score
        diff = abs(proba[0] - proba[1])

    if diff < 0.01:
        return "Unknown", -1, phishing_score

    pred = 1 if phishing_score > 0.5 else 0
    label = "Phishing" if pred == 1 else "Legitimate"
    return label, pred, phishing_score

def predict_url(url):
    print(f"🔍 Predicting URL: {url}")
    try:
        feature_dict = load_url_analysis(url)
        if feature_dict is None:
            feature_dict = extract_features(url)
            save_url_analysis(url, feature_dict)
        else:
            print(f"📦 Loaded cached analysis for: {url} — Skipping resolution")

        features = feature_dict["original_features"]
        processed_url = feature_dict["original_url"]

        df = pd.DataFrame([features])
        df.drop(columns=["URL Domain"], inplace=True)

        tld_value = df["TLD"].values[0]
        if tld_value not in le.classes_:
            if "unknown" not in le.classes_:
                le.classes_ = np.append(le.classes_, "unknown")
            df["TLD"] = "unknown"
        df["TLD"] = le.transform(df["TLD"].astype(str))

        df = df.reindex(columns=feature_order, fill_value=0)
        df_scaled = scaler.transform(df)

        proba1 = url_model1.predict_proba(df_scaled)[0]
        proba2 = url_model2.predict_proba(df_scaled)[0]

        label1, _, score1 = label_logic(proba1, features)
        label2, _, score2 = label_logic(proba2, features)

        raw_score1 = float(round(score1 * 100, 2))
        raw_score2 = float(round(score2 * 100, 2))

        if label1 == "Phishing" and raw_score1 < 60: label1 = "Suspicious"
        if label2 == "Phishing" and raw_score2 < 60: label2 = "Suspicious"

        if label1 == "Phishing" and label2 == "Phishing":
            final_label = "Phishing"
        elif label1 == "Legitimate" and label2 == "Legitimate":
            final_label = "Legitimate"
        else:
            final_label = "Suspicious"

        if final_label == "Legitimate":
            shown_score = 100 - ((raw_score1 + raw_score2) / 2)
        else:
            shown_score = (raw_score1 + raw_score2) / 2

        shown_score = float(round(shown_score, 2))

        return final_label, shown_score, feature_dict, feature_dict["resolved_url"]

    except Exception as e:
        print(f"URL prediction failed: {e}")
        return "Legitimate", 0.0, None, url

def get_keyword_category(keyword):
    return SPAM_KEYWORD_MAP.get(keyword.lower(), "Uncategorized")

def analyze_email(email_text, subject, sender_email, sender_name):
    combined_text = f"{subject.strip()}. {email_text.strip()}"
    matched_spam_keywords = []

    if SPAM_KEYWORDS:
        matched_spam_keywords = [kw for kw in SPAM_KEYWORDS if re.search(rf'\b{re.escape(kw)}\b', combined_text.lower())]
        spam_keyword_count = len(matched_spam_keywords)

    vect = tfidf.transform([combined_text])
    email_pred_proba = email_model.predict_proba(vect)[0]
    email_label_idx = int(np.argmax(email_pred_proba))
    label = email_model.classes_[email_label_idx]
    confidence = float(email_pred_proba[email_label_idx]) * 100

    reasoning = generate_reasoning(combined_text, label, spam_keyword_count)

    return {
        "email_label": label,
        "email_confidence": round(confidence, 2),
        "spam_keyword_count": spam_keyword_count,
        "matched_spam_keywords": matched_spam_keywords,
        "explanation": reasoning,
        "cleaned_email_text": email_text
    }

def generate_reasoning(text, label, spam_keyword_count):
    reasons = []
    text_lower = text.lower()

    if label in ["Phishing", "Suspicious"]:
        if any(word in text_lower for word in ["login", "verify", "password", "credentials", "passcode", "security code", "pin"]):
            reasons.append("🔐 Attempts to steal login credentials")

        if any(re.search(rf'\b{re.escape(word)}\b', text_lower) for word in ["bank", "account", "payment", "invoice", "transaction", "billing", "balance", "card", "funds", "pay now", "make payment"]):
            reasons.append("💰 Mentions financial-related terms")

        if any(word in text_lower for word in ["urgent", "act now", "immediately", "within 24 hours", "risk", "suspend", "warning", "failure to", "limited time", "final notice"]):
            reasons.append("⏰ Uses urgency or threats")

        if any(word in text_lower for word in ["click here", "verify now", "confirm identity", "login below", "update information", "secure your account", "reset now"]):
            reasons.append("🖱️ Contains common phishing phrases")

        if any(word in text_lower for word in ["win", "free", "congratulations", "reward", "cash", "voucher", "lucky draw", "promo", "exclusive offer"]):
            reasons.append("🎁 Contains reward or prize bait")

        if spam_keyword_count > 0:
            reasons.append(f"📛 Includes {spam_keyword_count} spam keywords")

    if not reasons:
        reasons.append("✅ No obvious phishing indicators found.")

    return reasons

def unwrap_google_redirect(url):
    match = re.search(r'https?://www\.google\.com/url\?q=(https?://[^&]+)', url)
    if match:
        return clean_url(match.group(1))
    return url

def unified_predict(request_data):
    email_text = request_data.get("email_text", "").strip()
    has_valid_body = bool(email_text)
    sender_email = request_data.get("sender", "unknown@example.com")
    sender_domain = sender_email.split("@")[-1].lower().strip()
    subject = request_data.get("subject", "").strip()

    # === Email content prediction ===
    if not has_valid_body and not subject:
        return {
            "error": "No email content or subject provided for analysis.",
            "verdict": "Unable to Analyze",
            "email_label": "Unknown",
            "email_confidence": 0.0,
            "reason_lines": ["No content available to analyze."],
            "anomaly": False
        }
    
    if not has_valid_body and subject:
        print(f"⚠️ Email body is empty. Using subject for prediction: '{subject.strip()}'")
        combined_text = subject.strip()
        highlighted_text = None
    elif subject and has_valid_body:
        combined_text = f"{subject.strip()}. {email_text.strip()}"
        highlighted_text = email_text.strip()
    elif has_valid_body:
        combined_text = email_text
        highlighted_text = email_text
    else:
        combined_text = ""
        highlighted_text = None

    subject_lower = subject.lower()
    extracted_urls = request_data.get("extracted_urls", []) 

    subject_spam_count = count_spam_keywords(subject_lower)
    subject_alert = subject_spam_count > 0

    vect = tfidf.transform([combined_text])
    email_pred = email_model.predict(vect)[0]
    email_proba = email_model.predict_proba(vect)[0]

    if email_pred == 1: 
        email_confidence = float(round(email_proba[1] * 100, 2))
    else: 
        email_confidence = float(round(email_proba[0] * 100, 2))

    if subject_alert and email_pred == 1:
        email_confidence += 5
        if email_confidence > 100:
            email_confidence = 100

    # === URL extraction and prediction ===
    raw_urls = extracted_urls if extracted_urls else extract_urls(email_text)
    urls = [unwrap_google_redirect(u) for u in raw_urls]
    url_preds = []

    for u in urls:
        try:
            label, conf, feature_dict, final_url = predict_url(u)
            if feature_dict is None:
                continue 

            screenshot = get_screenshot_base64(feature_dict["final_url"])

            print(f"🚨 Predicting final URL: {u}")
            print(f"🔗 Cleaned URL for prediction: {u}")

            url_preds.append((
                u, label, conf,
                feature_dict["original_features"],
                feature_dict["resolved_features"],
                feature_dict["original_url"],
                feature_dict["resolved_url"],
                screenshot,
                feature_dict["redirection_mismatch"],
                feature_dict["original_domain"],
                feature_dict["resolved_domain"]
            ))
        except Exception as e:
            print(f"[URL loop error] {e}")
            url_preds.append((
                u, "Legitimate", 0.0,
                {"error": "feature extraction failed"},
                {"error": "feature extraction failed"},
                u, u, None, False, "", ""
            ))

    # === Format for UI/Frontend ===
    url_labels = {
        u: {
            "label": lbl,
            "confidence": conf,
            "original_features": orig_feats,
            "resolved_features": res_feats,
            "original_url": orig_url,
            "final_url": res_url,
            "screenshot_base64": shot,
            "redirection_mismatch": mismatch,
            "original_domain": orig_dom,
            "resolved_domain": res_dom
        }
        for u, lbl, conf, orig_feats, res_feats, orig_url, res_url, shot, mismatch, orig_dom, res_dom in url_preds
    }

    # === Spam Keyword Count ===
    spam_keyword_count_body = count_spam_keywords(email_text)
    spam_keyword_count_subject = count_spam_keywords(subject)
    spam_keyword_count = spam_keyword_count_body + spam_keyword_count_subject

    # === Final verdict decision ===
    reason_lines = []
    phishing_urls = [u for u, p in url_labels.items() if p["label"] == "Phishing" and p["confidence"] >= 60]
    suspicious_urls = [u for u, p in url_labels.items() if p["label"] == "Suspicious"]
    has_suspicious_url = len(suspicious_urls) > 0

    try:
        profile, similarity = load_profiles(sender_email, email_text)
    except Exception as e:
        print("⚠️ Failed to load profile:", e)
        profile, similarity = None, 1.0

    if email_pred == 1 and spam_keyword_count == 0 and len(phishing_urls) == 0:
        all_urls_legit = all(p["label"] == "Legitimate" for p in url_labels.values())
        if all_urls_legit and similarity < 0.25:
            print("🟡 Downgrading email confidence due to clean content + anomaly")
            email_confidence = min(email_confidence, 65.0)

    # 1. Email and URL both malicious
    if email_pred == 1 and len(phishing_urls) == 1 and phishing_urls[0] in url_labels:
        score = url_labels[phishing_urls[0]]["confidence"]
        if score < 80:
            final_label = "Suspicious (⚠️ Low-risk phishing URL + phishing content)"
        else:
            final_label = "Phishing"

    # 2. Email content phishing + suspicious URL 
    elif email_pred == 1 and has_suspicious_url:
        final_label = "Suspicious (⚠️ Email & URL conflict)"

    # 3. Suspicious URL only
    elif len(phishing_urls) == 0 and has_suspicious_url:
        final_label = "Suspicious (⚠️ Suspicious URL detected)"

    # 4. Email suspicious only (no phishing/suspicious URL)
    elif len(phishing_urls) == 0:
        if email_pred == 1:
            if subject_alert or spam_keyword_count > 1:
                final_label = "Suspicious (⚠️ Content only)"
            else:
                final_label = "Suspicious"
        else:
            final_label = "Legitimate"

    # 5. Single phishing URL in many URLs
    elif len(phishing_urls) == 1 and len(url_labels) > 4:
        final_label = "Suspicious (⚠️ Suspicious URL detected)"

    # 6. High phishing ratio (more than 30%)
    elif len(phishing_urls) / max(len(url_labels), 1) > 0.3:
        final_label = "Phishing"

    # 7. Trusted Sender Domain
    elif email_pred == 1 and is_trusted_domain(sender_domain):
        phishing_count = len(phishing_urls)
        suspicious_count = len(suspicious_urls)

        is_urls_clean = phishing_count == 0 and suspicious_count == 0
        is_subject_clean = not subject_alert
        is_spam_low = spam_keyword_count <= 2

        if is_urls_clean and is_subject_clean and is_spam_low:
            if email_confidence >= 80:
                print(f"🟡 Trusted sender downgrade: high confidence but weak spam indicators")
                final_label = "Suspicious (⚠️ Downgraded due to trusted sender + clean content)"
                reason_lines.append("🟡 Downgraded due to trusted sender and weak phishing signal")
            else:
                print(f"✅ Trusted sender override applied for {sender_domain}: Clean URLs + clean content")
                final_label = "Legitimate"

    # 8. Default fallback
    else:
        final_label = "Suspicious"

    if email_text and subject and email_text.strip() == subject.strip():
        email_confidence = min(email_confidence, 70.0)
        email_label = "Suspicious"
        final_label = "Suspicious (⚠️ Empty body + suspicious subject)"
        reason_lines.insert(0, "✉️ Subject contains suspicious keywords but no email body is present.")

    # === Time email received ===
    raw_ts = request_data.get("email_timestamp")
    try:
        if raw_ts:
            dt_obj = datetime.fromtimestamp(float(raw_ts))
        else:
            dt_obj = datetime.now()
        formatted_time = dt_obj.strftime("%d %b %Y, %I:%M %p") 
    except Exception as e:
        print(f"⚠️ Timestamp error: {e}")
        formatted_time = "Unavailable"

    # === Detected Language ===
    try:
        email_lang_code = detect(email_text)
    except Exception as e:
        email_lang_code = "unknown"

    LANG_MAP = {
        "en": "English",
        "ms": "Malay",
        "zh": "Chinese",
        "id": "Indonesian",
        "ta": "Tamil",
        "es": "Spanish",
        "fr": "French",
        "de": "German",
        "vi": "Vietnamese",
        "unknown": "Unknown"
    }
    email_lang = LANG_MAP.get(email_lang_code, email_lang_code.title())

    # === Highlight matched spam keywords ===
    highlighted_email_body = None
    matched_spam_keywords_with_category = []

    if highlighted_text:
        highlighted_email_body = highlighted_text
        for kw in SPAM_KEYWORDS:
            if kw in combined_text.lower():
                category = get_keyword_category(kw)
                matched_spam_keywords_with_category.append((kw, category))
                highlighted_email_body = re.sub(
                    rf'\b({re.escape(kw)})\b',
                    r'<span style="color:red;"><strong>\1</strong></span>',
                    highlighted_email_body,
                    flags=re.IGNORECASE
                )

    # === Reason generation===
    explanation = generate_reasoning(email_text, final_label, spam_keyword_count)
    reason_lines = explanation.copy()
    if subject_alert:
        reason_lines.insert(0, f"✉️ Suspicious keywords found in subject ({subject_spam_count})")

    if profile is not None:
        entry = {
            "timestamp": raw_ts if raw_ts else int(time.time()),
            "subject": subject,
            "verdict": final_label
        }
        if entry not in profile["history"]:
            profile["history"].append(entry)
    save_profiles(sender_email, email_text, subject, final_label, timestamp=raw_ts)

    anomaly_flag = False
    if similarity < 0.75 and profile is not None:
        anomaly_flag = True
        print(f"⚠️ Behavior anomaly detected for {sender_email} (similarity: {similarity:.2f})")

    # === False Positive suppression rule ===
    is_clean_email = spam_keyword_count == 0
    is_all_https = all(v.get("resolved_features", {}).get("Has HTTPS", 0) == 1 for v in url_labels.values())
    is_all_trusted = all(is_trusted_domain(v.get("resolved_domain", "")) for v in url_labels.values())
    is_all_legit = all(v.get("label") == "Legitimate" for v in url_labels.values())

    if is_clean_email and is_all_https and is_all_trusted and similarity > 0.45 and final_label == "Phishing":
        print("🟡 Suppression rule triggered — likely false positive")
        final_label = "Suspicious (⚠️ Legit email flagged due to structure)"
        reason_lines.append("🟡 Suppression rule applied: clean content + trusted internal domain")

    if (
        email_pred == 1
        and email_confidence > 85
        and spam_keyword_count <= 1
        and all(label.get("label") == "Legitimate" for label in url_labels.values())
        and all(is_trusted_domain(label.get("resolved_domain", "")) for label in url_labels.values())
    ):
        print("🟡 Suppression triggered: high-confidence phishing with weak signal and trusted URLs")
        final_label = "Suspicious (⚠️ Weak signal in clean email)"
        email_confidence = min(email_confidence, 75.0)
        reason_lines.append("🟡 Downgraded: weak phishing content and all trusted domains")

    if email_pred == 1 or (email_text and subject and email_text.strip() == subject.strip()):
        if "Suspicious" in final_label:
            email_label = "Suspicious"
        else:
            email_label = "Phishing"
    else:
        email_label = "Legitimate"

    return {
        "email_text": email_text,
        "email_label": email_label,
        "email_confidence": email_confidence,
        "url_predictions": url_labels,
        "final_decision": final_label,
        "spam_keyword_count": spam_keyword_count,
        "explanation": "<br>".join(reason_lines),
        "reason_lines": reason_lines,
        "verdict": final_label,
        "summary": explanation,
        "anomaly_detected": anomaly_flag,
        "similarity_score": similarity,
        "anomaly": anomaly_flag,
        "sender": sender_email,
        "sender_name": request_data.get("sender_name", "Unknown Sender"),
        "email_subject": subject,
        "subject_spam_count": subject_spam_count,
        "subject_alert": subject_alert,
        "matched_spam_keywords": matched_spam_keywords_with_category,
        "highlighted_email_body": highlighted_email_body,
        "email_received_time": formatted_time,
        "email_language": email_lang,
        "tfidf_features": vect.toarray().tolist()[0],
        "vector": email_proba.tolist()
    }