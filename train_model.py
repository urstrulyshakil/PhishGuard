import os
import pickle
import hashlib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score

DATA_PATH = "data/phishing.csv"
MODEL_PATH = "modules/phish_model.pkl"
HASH_PATH = "modules/data_hash.txt"

def file_hash(path):
    """Compute SHA256 hash of file contents"""
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

print(f"📂 Checking dataset: {DATA_PATH} ...")

if not os.path.exists(DATA_PATH):
    print("❌ Dataset not found. Skipping training.")
    exit(1)

# Compute hash of dataset
current_hash = file_hash(DATA_PATH)
old_hash = None
if os.path.exists(HASH_PATH):
    with open(HASH_PATH, "r") as f:
        old_hash = f.read().strip()

# Skip retraining if dataset unchanged
if current_hash == old_hash and os.path.exists(MODEL_PATH):
    print("✅ Dataset unchanged. Skipping retraining. Using cached model.")
else:
    print("🔄 Training new model ...")

    df = pd.read_csv(DATA_PATH)
    X = df.drop("Is_Phishing", axis=1)
    y = df["Is_Phishing"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    model = LogisticRegression(max_iter=1000)
    model.fit(X_train, y_train)

    acc = accuracy_score(y_test, model.predict(X_test))
    print(f"✅ Model trained with accuracy: {acc:.2f}")

    # Save model
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)
    print(f"💾 Model saved to {MODEL_PATH}")

    # Save dataset hash
    with open(HASH_PATH, "w") as f:
        f.write(current_hash)