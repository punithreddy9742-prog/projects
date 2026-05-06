from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
import joblib
import re
import urllib.parse
from urllib.parse import urlparse
import tldextract
import whois
from datetime import datetime
import math
import ssl
import socket
import logging
from typing import Dict, Any
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    filename="phishnet.log"
)
logger = logging.getLogger("phishnet-ai")

# Initialize FastAPI app
app = FastAPI(
    title="PhishNet AI - Phishing Detection API",
    description="Advanced API for detecting phishing URLs using Machine Learning",
    version="1.1.0"
)

# CORS settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: In production, replace with your frontend domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Models
class URLInput(BaseModel):
    url: str

    @validator('url')
    def validate_url(cls, v):
        if not v:
            raise ValueError("URL cannot be empty")
        if not v.startswith(('http://', 'https://')):
            v = 'http://' + v
        parsed = urlparse(v)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("Invalid URL format")
        return v

class ScanResponse(BaseModel):
    url: str
    prediction: str
    confidence: float
    risk_score: float
    features: Dict[str, Any]
    scan_time: float
    timestamp: str

class ErrorResponse(BaseModel):
    error: str
    message: str
    timestamp: str

# Load model
try:
    model_path = r'C:\Users\Stevens\Desktop\PhishNet-AI\backend\models\url_model.pkl'
    model = joblib.load(model_path)
    logger.info(f"Model loaded successfully from {model_path}")
except Exception as e:
    logger.error(f"Failed to load model: {e}")
    model = None

# Phishing terms list
PHISHING_TERMS = [

    # --- Financial Institutions & Wallets ---
    'bank', 'banking', 'netbanking', 'netbaking', 'upi', 'paytm', 'phonepe', 'gpay', 'googlepay', 'bhim',
    'sbi', 'hdfc', 'icici', 'kotak', 'axisbank', 'canarabank', 'unionbank', 'pnb', 'idfc', 'bob', 'boi',
    'yono', 'instapay', 'wallet', 'razorpay', 'mobikwik', 'freecharge', 'cashfree',

    # --- E-commerce & Tech Giants (spoofed) ---
    'amazon', 'apple', 'ebay', 'flipkart', 'myntra', 'snapdeal', 'alibaba', 'meesho', 
    'netflix', 'hulu', 'spotify', 'zomato', 'swiggy', 'ola', 'uber',

    # --- Payment & FinTech Services ---
    'paypal', 'venmo', 'stripe', 'cashapp', 'squareup', 'skrill', 'wise', 'payoneer', 'payu',

    # --- Spoofed Government & Tax Services ---
    'aadhar', 'aadhaar', 'aadhaar-update', 'pan', 'kyc', 'incometax', 'incomtax', 'gst', 'gstin',
    'ssn', 'socialsecurity', 'lic', 'epfo', 'esic', 'passport', 'voterid', 'itreturn', 'gov', 'govt',

    # --- Spoofed Domains (Top-Level or Full) ---
    '.pk', '.xyz', '.top', '.click', '.info', '.ml', '.ga', '.cf', '.gq', '.tk',
    'google.com-security-alerts.com', 'paypall.com', 'amaz0n.net', 'appleid-login.com',
    'secure-icici.com', 'update-hdfc.net', 'sbi-online-banking.com', 'aadhar-verification.com',

    # --- Common Account/User Actions ---
    'login', 'signin', 'verify', 'update', 'confirm', 'reactivate', 'reset', 'unlock', 'deactivated', 
    'blocked', 'access-now', 'download-now', 'click-here', 'act-now', 'limited-time', 'important-update',

    # --- Security/Access Language ---
    'password', 'credentials', 'credential', 'secure', 'security-alert', 'unusual-activity',
    'support', 'helpdesk', 'helpline', 'email-update', 'authentication',

    # --- Scam/Reward Language ---
    'refund', 'cashback', 'reward', 'lottery', 'winner', 'jackpot', 'prize', 'claim-now', 'free-gift',
    'survey', 'scheme', 'trust', 'beneficiary',

    # --- Urgency & Psychological Triggers ---
    'urgent', 'important', 'immediate', 'warning', 'alert', 'suspicious', 'final-notice', 'action-required',

    # --- Social Media Spoofing (Phishing Lures) ---
    'facebook', 'instagram', 'twitter', 'linkedin', 'snapchat', 'tiktok', 'youtube', 'meta', 'whatsapp',
    'telegram', 'messenger',

    # --- Known Variants & Misspellings ---
    'netbaking', 'incomtax', 'signin', 'passw0rd', 'secur3', 'ver1fy', 'acc0unt', 'paypall', 'g00glepay',
    'ph0nepe', 'rewards', 'act1vate', 'kyyc', 'adhaar', 'adhar', 'ammount', 'refunnd', 'cl1ck'
]



# Helper functions
def check_ssl(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return True, cert.get('notAfter', '')
    except Exception:
        return False, None

def calculate_entropy(text):
    if not text:
        return 0
    entropy = 0
    text = text.lower()
    char_count = {}
    for char in text:
        char_count[char] = char_count.get(char, 0) + 1
    for count in char_count.values():
        p_x = float(count) / len(text)
        entropy += -p_x * math.log(p_x, 2)
    return entropy

def extract_features(url: str) -> Dict[str, Any]:
    features = {}
    start_time = time.time()

    # Basic characteristics
    features['url_length'] = len(url)
    features['has_https'] = int(url.startswith('https'))
    features['has_http'] = int(url.startswith('http:'))
    features['has_ip_address'] = int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', url)))

    # Character counts
    features['count_hyphens'] = url.count('-')
    features['count_at'] = url.count('@')
    features['count_dots'] = url.count('.')
    features['count_digits'] = sum(c.isdigit() for c in url)
    features['count_slash'] = url.count('/')
    features['count_question_mark'] = url.count('?')
    features['count_equal_sign'] = url.count('=')
    features['count_underscore'] = url.count('_')
    features['count_ampersand'] = url.count('&')
    features['count_percent'] = url.count('%')

    # URL parsing
    try:
        parsed = urlparse(url)
        extracted = tldextract.extract(url)
        features['domain_length'] = len(extracted.domain)
        features['tld_length'] = len(extracted.suffix)
        features['path_length'] = len(parsed.path)
        features['query_length'] = len(parsed.query)
        features['subdomain_length'] = len(extracted.subdomain)
        features['has_multiple_subdomains'] = int(len(extracted.subdomain.split('.')) > 1)
        features['has_unusual_port'] = int(parsed.port not in [80, 443] if parsed.port else 0)
        features['phishing_term_in_subdomain'] = int(
            any(term in extracted.subdomain.lower() for term in PHISHING_TERMS)
        )
    except Exception as e:
        logger.warning(f"Error parsing URL {url}: {e}")
        for key in ['domain_length', 'tld_length', 'path_length', 'query_length',
                    'subdomain_length', 'has_multiple_subdomains', 'has_unusual_port']:
            features[key] = 0

    # Suspicious terms
    for term in PHISHING_TERMS:
        features[f'has_{term}'] = int(term in url.lower())

    # Advanced features
    features['has_hex_chars'] = int(bool(re.search(r'%[0-9a-fA-F]{2}', url)))
    features['url_entropy'] = calculate_entropy(url)

    # WHOIS information
    try:
        domain = extracted.registered_domain
        if domain:
            domain_info = whois.whois(domain)
            creation_date = domain_info.creation_date
            expiration_date = domain_info.expiration_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            if creation_date and expiration_date:
                features['domain_age_days'] = (expiration_date - creation_date).days
                features['domain_expiring_soon'] = int((expiration_date - datetime.now()).days < 90)
            else:
                features['domain_age_days'] = -1
                features['domain_expiring_soon'] = 0
        else:
            features['domain_age_days'] = -1
            features['domain_expiring_soon'] = 0
    except Exception as e:
        logger.warning(f"WHOIS lookup failed for {url}: {e}")
        features['domain_age_days'] = -1
        features['domain_expiring_soon'] = 0

    # SSL Certificate
    try:
        if domain:
            has_valid_ssl, _ = check_ssl(domain)
            features['has_valid_ssl'] = int(has_valid_ssl)
        else:
            features['has_valid_ssl'] = 0
    except Exception as e:
        logger.warning(f"SSL check failed for {url}: {e}")
        features['has_valid_ssl'] = 0

    features['extraction_time'] = time.time() - start_time
    return features

def calculate_risk_score(features: Dict[str, Any]) -> float:
    score = 0
    if features['has_ip_address']:
        score += 25
    if features['count_at'] > 0:
        score += 20
    if not features['has_https']:
        score += 15
    if features.get('domain_age_days', -1) < 30 and features.get('domain_age_days', -1) != -1:
        score += 20
    if features.get('has_valid_ssl', 0) == 0:
        score += 15
    if features['url_length'] > 75:
        score += 10
    if features['count_dots'] > 3:
        score += 5
    if features['has_multiple_subdomains']:
        score += 10
    if features['has_unusual_port']:
        score += 15

    suspicious_terms = sum(
        1 for k, v in features.items() if k.startswith('has_') and v and k not in {
            'has_https', 'has_http', 'has_ip_address', 
            'has_multiple_subdomains', 'has_unusual_port', 'has_valid_ssl', 'has_hex_chars'
        }
    )
    score += suspicious_terms * 5

    return min(100, score)

# Routes
@app.post("/scan", response_model=ScanResponse)
async def scan_url(input_data: URLInput):
    if model is None:
        logger.error("Model not loaded.")
        raise HTTPException(status_code=500, detail="Model not loaded.")

    try:
        url = input_data.url
        start_time = time.time()

        features = extract_features(url)

        # ⚠️ You should order features properly based on model input
        model_features = list(features.values())[:30]

        prediction_value = model.predict([model_features])[0]
        prediction = "Phishing" if prediction_value == 1 else "Safe"

        try:
            confidence = float(model.predict_proba([model_features])[0][prediction_value])
        except Exception:
            confidence = 1.0

        risk_score = calculate_risk_score(features)
        scan_time = time.time() - start_time

        logger.info(f"Scanned {url}: {prediction} with risk {risk_score}")

        return {
            "url": url,
            "prediction": prediction,
            "confidence": confidence,
            "risk_score": risk_score,
            "features": features,
            "scan_time": scan_time,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to scan URL: {str(e)}")

@app.get("/health")
async def health_check():
    return {"status": "healthy", "model_loaded": model is not None}

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"error": "Internal Server Error", "message": str(exc), "timestamp": datetime.now().isoformat()}
    )

# Entrypoint
if __name__ == "__main__":
    import uvicorn
    logger.info("Starting PhishNet AI API server...")
    uvicorn.run(app, host="0.0.0.0", port=8000)
