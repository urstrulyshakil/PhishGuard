import os
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

MODEL_PATH = os.path.join(os.path.dirname(__file__), "phish_model.pkl")

def train_model(dataset_path: str):
    """
    Train a phishing detection model from scratch using Logistic Regression.
    Dataset must have: 'url' and 'label' columns
    - label: 1 (phishing), 0 (legit)
    """
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Dataset not found at {dataset_path}")

    # Load dataset
    data = pd.read_csv(dataset_path)

    # Basic checks
    if "url" not in data.columns or "label" not in data.columns:
        raise ValueError("Dataset must contain 'url' and 'label' columns.")

    X = data["url"]
    y = data["label"]

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    # Pipeline: Vectorizer + Logistic Regression
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), max_features=5000)),
        ("clf", LogisticRegression(max_iter=1000))
    ])

    # Train
    pipeline.fit(X_train, y_train)

    # Save model
    joblib.dump(pipeline, MODEL_PATH)

    acc = pipeline.score(X_test, y_test)
    print(f"✅ Model trained & saved at {MODEL_PATH} | Accuracy: {acc:.2f}")

def load_model():
    """Load trained phishing detection model."""
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError("Trained model not found. Run train_model first.")
    return joblib.load(MODEL_PATH)

def predict_url(url: str):
    """
    Predict if a URL is phishing or legitimate.
    Returns: (prediction, probability)
    """
    model = load_model()
    prediction = model.predict([url])[0]
    probability = model.predict_proba([url])[0][prediction]
    return prediction, probability