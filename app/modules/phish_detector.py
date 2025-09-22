# modules/phish_detector.py
import os
import re
import requests
import joblib
from urllib.parse import urlparse

MODEL_PATH = os.path.join(os.path.dirname(__file__), "phish_model.pkl")

# Try to load model if present (optional)
_pipeline = None
if os.path.exists(MODEL_PATH):
    try:
        _pipeline = joblib.load(MODEL_PATH)
    except Exception:
        _pipeline = None

# --- Safe small network probe (HEAD only) ---
def safe_probe(url, timeout=4):
    try:
        if not re.match(r"^https?://", url):
            url = "http://" + url
        r = requests.head(url, allow_redirects=False, timeout=timeout, verify=True)
        return {"status": r.status_code, "headers": dict(r.headers)}
    except Exception as e:
        return {"error": str(e)}

# --- Lightweight feature extractor (matches starter CSV) ---
def extract_features(url):
    u = str(url).strip()
    return {
        "URL_Length": len(u),
        "Has_AtSymbol": int("@" in u),
        "Has_DoubleSlash": int(u.count("//") > 1),
        "Num_Dots": u.count("."),
        "Has_IP": int(bool(re.match(r"^(?:http[s]?://)?\d{1,3}(?:\.\d{1,3}){3}", u))),
        "Has_LoginKeyword": int(bool(re.search(r"(login|signin|secure|account|verify)", u, re.I)))
    }

# --- Main check function: tries heuristics first, then model if available ---
def check_url(url):
    """
    Input: URL string
    Returns: (status_str, details_str)
    """
    # 1) quick heuristics
    f = extract_features(url)
    if f["Has_AtSymbol"]:
        return "Phishing", "Contains '@' symbol"
    if f["Has_IP"]:
        return "Phishing", "Uses direct IP in URL"
    if f["Has_LoginKeyword"]:
        return "Phishing", "Contains suspicious keyword"
    if f["URL_Length"] > 200:
        return "Phishing", "Very long URL"

    # 2) optional network probe (non-invasive)
    probe = safe_probe(url)
    if "error" in probe:
        # ignore probe errors; continue
        pass
    else:
        code = probe.get("status")
        if code and (code >= 400 and code < 600):
            # 4xx/5xx could be suspicious if combined with heuristics, keep soft rule
            return "Unknown", f"HTTP status {code}"

    # 3) If a trained model exists, use it
    if _pipeline is not None:
        try:
            import pandas as pd
            X = pd.DataFrame([{
                "URL_Length": f["URL_Length"],
                "Has_AtSymbol": f["Has_AtSymbol"],
                "Has_DoubleSlash": f["Has_DoubleSlash"],
                "Num_Dots": f["Num_Dots"],
                "Has_IP": f["Has_IP"],
            }])
            pred = _pipeline.predict(X)[0]
            prob = None
            try:
                prob = _pipeline.predict_proba(X)[0][int(pred)]
            except Exception:
                prob = None
            label = "Phishing" if int(pred) == 1 else "Legitimate"
            details = f"ML:{prob:.2f}" if prob is not None else "ML:unknown"
            return label, details
        except Exception as e:
            return "Error", f"ML error: {e}"

    # 4) Fallback
    return "Unknown", "No strong heuristic or model decision"