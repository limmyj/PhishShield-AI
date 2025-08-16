import re
import time
import joblib
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.naive_bayes import MultinomialNB
from sklearn.neural_network import MLPClassifier
from sklearn.svm import LinearSVC
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, ConfusionMatrixDisplay

df = pd.read_csv("C:\\Users\\Athelene\\Downloads\\phishEmail.csv")
df.dropna(subset=['text'], inplace=True)

def clean_email_text(text):
    text = re.sub(r'[^A-Za-z0-9\s]', ' ', text)
    text = re.sub(r'\s+', ' ', text)
    return text.strip().lower()

df['clean_text'] = df['text'].apply(clean_email_text)

X = df['clean_text']
y = df['label']

tfidf = TfidfVectorizer(max_features=5000, stop_words='english')
X_tfidf = tfidf.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(X_tfidf, y, test_size=0.2, random_state=42)

models = {
    "Logistic Regression": LogisticRegression(max_iter=1000),
    "Multinomial NB": MultinomialNB(),
    "Linear SVM": LinearSVC(max_iter=1000),
    "Random Forest": RandomForestClassifier(n_estimators=100),
    "Gradient Boosting": GradientBoostingClassifier(),
    "MLP Classifier": MLPClassifier(max_iter=300)
}

results = {}
for name, model in models.items():
    print(f"Training: {name}")
    start = time.time()
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred, output_dict=True)
    cm = confusion_matrix(y_test, y_pred)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["Legitimate", "Phishing"])

    print(f"\nConfusion Matrix for {name}:")
    disp.plot(cmap='Blues')
    plt.title(f"{name} Confusion Matrix")
    plt.show()

    results[name] = {
        'Accuracy': acc,
        'Precision': report['weighted avg']['precision'],
        'Recall': report['weighted avg']['recall'],
        'F1-Score': report['weighted avg']['f1-score'],
        'Time Taken (s)': round(time.time() - start, 2)
    }
    joblib.dump(model, f"{name.replace(' ', '_').lower()}_model.pkl")

joblib.dump(tfidf, "tfidf_vectorizer.pkl")

results_df = pd.DataFrame(results).T.sort_values(by='Accuracy', ascending=False)
results_df.reset_index(inplace=True)
results_df.rename(columns={"index": "Model"}, inplace=True)
print(results_df)