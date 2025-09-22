# 🛡️ PhishGuard

PhishGuard is a lightweight **phishing URL detection app** built with **Streamlit** and a simple **ML model**.  
It detects phishing websites using heuristics + trained features.  
Free, open-source, and containerized with Docker 🚀

---

## 📂 Project Structure
PhishGuard/
│── app/
│   └── main.py          # Streamlit frontend
│── modules/
│   ├── phish_detector.py
│   ├── ml_model.py
│   └── phish_model.pkl  # Saved model (auto-generated)
│── data/
│   └── phishing.csv     # Training dataset
│── train_model.py       # Train/update model
│── requirements.txt
│── Dockerfile
│── README.md

---

## ⚡ Features
- Streamlit UI for phishing detection
- ML-based detection (Logistic Regression by default)
- Auto-retraining if `data/phishing.csv` changes
- Dockerized for easy deployment

---

## 🛠️ Installation (Local)

1. Clone repo:
   ```bash
   git clone https://github.com/urstrulyshakil/PhishGuard.git
   cd PhishGuard

2.	Create virtual environment:
python3 -m venv venv
source venv/bin/activate

3.	Install dependencies:
pip install -r requirements.txt

4.	Train model:
python train_model.py

5.	Run app:
streamlit run app/main.py


🐳 Run with Docker

1. Build the image
docker build -t phishguard:latest .

2. Remove any old container
docker rm -f phishguard

3. Run container with volumes
docker run -d -p 8501:8501 --name phishguard \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/modules:/app/modules \
  phishguard:latest

👉 App will be available at: http://localhost:8501


📈 Model Training
	•	The model auto-trains on container start if data/phishing.csv changed.
	•	Cached model (modules/phish_model.pkl) is reused if dataset unchanged.

Train manually (optional):
python train_model.py

⚠️ Security Note
	•	This is a demo project — don’t test with real phishing URLs on your host machine.
	•	For safety, test inside Docker or with sanitized datasets.


📜 License

MIT License © 2025 Shakil Ahmed
