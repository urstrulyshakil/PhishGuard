import sys
import os
import re
import streamlit as st

# Add project root (parent of app/) to sys.path so 'modules' can be imported
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Import modules
from modules.phish_detector import check_url

# Streamlit page configuration
st.set_page_config(
    page_title="PhishGuard",
    page_icon="🛡️",
    layout="wide"
)

# App title and description
st.title("PhishGuard 🛡️")
st.markdown("Enter a URL to check if it's phishing or legitimate.")

# URL input from user
url = st.text_input("Enter URL:")

# Feature extraction function
def extract_features(url: str) -> dict:
    features = {}
    features["URL_Length"] = len(url)
    features["Has_AtSymbol"] = int("@" in url)
    features["Has_DoubleSlash"] = int(url.count("//") > 1)
    features["Num_Dots"] = url.count(".")
    features["Has_IP"] = int(bool(re.match(r"^(?:http[s]?://)?\d{1,3}(?:\.\d{1,3}){3}", url)))
    return features

# Process URL input
if url:
    features = extract_features(url)
    status, details = check_url(features)
    if status.startswith("Phishing"):
        st.error(f"{status} - {details}")
    elif status.startswith("Legitimate"):
        st.success(f"{status} - {details}")
    else:
        st.warning(f"{status} - {details}")

st.markdown("---")
st.markdown("⚠️ Demo app. Replace ML hook in `modules/ml_model.py` with actual trained model for production.")