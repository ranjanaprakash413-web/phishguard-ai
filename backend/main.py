import re, math
from urllib.parse import urlparse
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="PhishGuard AI API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

class Scan(BaseModel):
    url: str = ""
    message: str = ""

BAD_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "zip", "support"}
BRANDS = ["paypal", "google", "amazon", "microsoft", "apple", "netflix", "facebook", "instagram", "sbi", "hdfc", "icici"]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly"}
URGENT = ["urgent", "immediately", "verify your", "suspended", "locked", "expire", "confirm your",
          "act now", "limited time", "password", "otp", "click here", "winner", "prize", "gift card", "kyc"]

def url_features(url):
    f = []  # (weight, reason)
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    u = urlparse(url)
    host = (u.hostname or "").lower()
    if u.scheme == "http": f.append((1.0, "Uses insecure HTTP instead of HTTPS"))
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host): f.append((2.0, "Uses a raw IP address instead of a domain"))
    if "@" in url: f.append((1.5, "Contains '@' which can hide the real destination"))
    if host.count(".") >= 4: f.append((1.2, "Too many subdomains"))
    if len(url) > 75: f.append((0.8, "Unusually long URL"))
    if host in SHORTENERS: f.append((1.2, "Shortened link hides the real site"))
    if host.split(".")[-1] in BAD_TLDS: f.append((1.3, "Domain extension often abused by scammers"))
    if "xn--" in host: f.append((1.5, "Look-alike (punycode) characters in domain"))
    if host.count("-") >= 2: f.append((0.9, "Multiple hyphens in domain"))
    for b in BRANDS:
        root = ".".join(host.split(".")[-2:])
        if b in host and not root.startswith(b + "."):
            f.append((2.0, f"Imitates the brand '{b}' on an unofficial domain")); break
    return f

def text_features(msg):
    m = msg.lower(); f = []
    hits = [w for w in URGENT if w in m]
    if hits: f.append((min(0.6 * len(hits), 2.5), "Pressure / sensitive keywords: " + ", ".join(hits[:4])))
    if re.search(r"https?://", m): f.append((0.5, "Message contains a link"))
    if m.count("!") >= 3: f.append((0.6, "Excessive exclamation marks"))
    return f

@app.get("/")
def root(): return {"service": "PhishGuard AI", "status": "ok"}

@app.get("/health")
def health(): return {"status": "healthy"}

@app.post("/api/analyze")
def analyze(s: Scan):
    feats = (url_features(s.url.strip()) if s.url.strip() else []) + (text_features(s.message) if s.message.strip() else [])
    z = sum(w for w, _ in feats) - 2.2          # logistic-regression style scoring
    risk = round(100 / (1 + math.exp(-z)))
    level = "High" if risk >= 70 else "Medium" if risk >= 40 else "Low"
    advice = {"High": "Do NOT click or reply. Report it and delete it.",
              "Medium": "Be careful. Verify with the official website or app.",
              "Low": "Looks fine, but always stay alert."}[level]
    return {"risk": risk, "level": level, "reasons": [r for _, r in feats] or ["No suspicious signs found"], "advice": advice}

@app.get("/api/quiz")
def quiz():
    return [
     {"q": "An email says 'Your account is locked! Verify in 10 minutes.' What do you do?",
      "o": ["Click the link fast", "Open the official site yourself", "Reply with your password"], "a": 1},
     {"q": "Which URL is safest?", "o": ["paypal.com.secure-login.xyz", "https://www.paypal.com", "http://192.168.4.7/paypal"], "a": 1},
     {"q": "Someone calls asking for your OTP to 'fix' your bank. You should:", "o": ["Share it", "Hang up, never share OTPs", "Share half"], "a": 1}]
