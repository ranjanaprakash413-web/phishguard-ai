// PhishGuard AI — backend
// Heuristic, explainable phishing-risk scoring engine + cyber-awareness content API.

const express = require("express");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json({ limit: "200kb" }));

const PORT = process.env.PORT || 4000;

// ---------- Detection rule set ----------
// Each rule inspects the submitted text/URL and contributes weighted points
// toward a 0-100 risk score, with a human-readable reason attached.

const URGENCY_WORDS = [
  "urgent", "immediately", "verify your account", "suspended", "act now",
  "limited time", "click here", "confirm your identity", "unusual activity",
  "you have won", "claim your prize", "final notice", "restricted",
  "unauthorized login", "update your payment", "expire", "locked"
];

const SENSITIVE_ASK_WORDS = [
  "password", "ssn", "social security", "otp", "one time password",
  "cvv", "pin number", "bank account", "credit card number", "login credentials"
];

const SUSPICIOUS_TLDS = [".xyz", ".top", ".zip", ".club", ".gq", ".tk", ".work", ".click", ".rest"];

const URL_REGEX = /(https?:\/\/[^\s]+)/gi;

function extractUrls(text) {
  return text.match(URL_REGEX) || [];
}

function analyzeUrl(rawUrl) {
  const reasons = [];
  let score = 0;
  let hostname = "";
  try {
    const u = new URL(rawUrl);
    hostname = u.hostname.toLowerCase();

    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
      score += 25;
      reasons.push("Link uses a raw IP address instead of a domain name");
    }

    if (u.protocol !== "https:") {
      score += 10;
      reasons.push("Link does not use HTTPS");
    }

    const hyphenCount = (hostname.match(/-/g) || []).length;
    if (hyphenCount >= 3) {
      score += 10;
      reasons.push("Domain name has an unusually high number of hyphens");
    }

    if (SUSPICIOUS_TLDS.some((tld) => hostname.endsWith(tld))) {
      score += 15;
      reasons.push(`Domain uses a top-level domain often abused for phishing (${hostname.split(".").pop()})`);
    }

    const knownBrands = ["paypal", "amazon", "google", "microsoft", "apple", "netflix", "bank", "facebook", "instagram"];
    const brandInSubdomain = knownBrands.find(
      (b) => hostname.includes(b) && !hostname.endsWith(`${b}.com`) && !hostname.endsWith(`${b}.co`)
    );
    if (brandInSubdomain) {
      score += 25;
      reasons.push(`Brand name "${brandInSubdomain}" appears in the domain but isn't the real ${brandInSubdomain} domain (a classic lookalike-domain trick)`);
    }

    if (hostname.length > 30) {
      score += 8;
      reasons.push("Domain name is unusually long");
    }

    if (/\d{4,}/.test(hostname)) {
      score += 8;
      reasons.push("Domain contains a long numeric string");
    }
  } catch (e) {
    score += 5;
    reasons.push("Link could not be parsed as a valid URL");
  }
  return { score, reasons, hostname };
}

function analyzeText(input) {
  const text = (input || "").toString();
  const lower = text.toLowerCase();
  let score = 0;
  const findings = [];

  const urgencyHits = URGENCY_WORDS.filter((w) => lower.includes(w));
  if (urgencyHits.length) {
    const add = Math.min(30, urgencyHits.length * 8);
    score += add;
    findings.push({
      type: "Urgency / pressure language",
      detail: `Found ${urgencyHits.length} urgency phrase(s): ${urgencyHits.slice(0, 5).join(", ")}`,
      weight: add
    });
  }

  const sensitiveHits = SENSITIVE_ASK_WORDS.filter((w) => lower.includes(w));
  if (sensitiveHits.length) {
    const add = Math.min(30, sensitiveHits.length * 12);
    score += add;
    findings.push({
      type: "Requests sensitive information",
      detail: `Message asks for: ${sensitiveHits.slice(0, 5).join(", ")}`,
      weight: add
    });
  }

  if (/dear (customer|user|valued|sir\/madam)/i.test(text) || /^dear\s/i.test(text.trim())) {
    score += 8;
    findings.push({
      type: "Generic greeting",
      detail: 'Uses a generic greeting instead of your actual name — legitimate services usually personalize this',
      weight: 8
    });
  }

  const exclaimCount = (text.match(/!/g) || []).length;
  if (exclaimCount >= 3) {
    score += 6;
    findings.push({
      type: "Excessive punctuation",
      detail: `${exclaimCount} exclamation marks detected — often used to create false urgency`,
      weight: 6
    });
  }

  const urls = extractUrls(text);
  let urlFindings = [];
  urls.forEach((rawUrl) => {
    const result = analyzeUrl(rawUrl);
    score += result.score;
    if (result.reasons.length) {
      urlFindings.push({ url: rawUrl, hostname: result.hostname, reasons: result.reasons, weight: result.score });
    }
  });

  score = Math.max(0, Math.min(100, Math.round(score)));

  let verdict = "Low Risk";
  if (score >= 70) verdict = "High Risk";
  else if (score >= 35) verdict = "Medium Risk";

  return {
    score,
    verdict,
    urlsFound: urls.length,
    findings,
    urlFindings,
    analyzedAt: new Date().toISOString()
  };
}

// ---------- Routes ----------

app.get("/", (req, res) => {
  res.json({ service: "PhishGuard AI backend", status: "running" });
});

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", uptime: process.uptime() });
});

app.post("/api/analyze", (req, res) => {
  const { content } = req.body || {};
  if (!content || typeof content !== "string" || !content.trim()) {
    return res.status(400).json({ error: "Provide 'content' (email text, message, or URL) to analyze." });
  }
  if (content.length > 20000) {
    return res.status(400).json({ error: "Content too long (max 20,000 characters)." });
  }
  const result = analyzeText(content);
  res.json(result);
});

app.get("/api/tips", (req, res) => {
  res.json({
    tips: [
      { title: "Check the sender's real address", body: "Don't trust the display name. Tap/hover to see the actual email address behind it." },
      { title: "Hover before you click", body: "Preview a link's real destination before clicking — the visible text can say anything." },
      { title: "Slow down on urgency", body: "Phishing relies on panic. A message demanding immediate action is a red flag, not a reason to rush." },
      { title: "No legitimate service asks for your password by email", body: "Banks, platforms, and IT teams never ask you to reply with your password, OTP, or PIN." },
      { title: "Verify through a separate channel", body: "If a message claims to be from your bank or employer, contact them directly using a number or site you already trust — not the one in the message." },
      { title: "Look for lookalike domains", body: "paypa1.com, arnazon.com, micros0ft-support.com — small character swaps are a common trick." },
      { title: "Enable multi-factor authentication", body: "Even if a password is stolen, MFA can stop the login attempt." },
      { title: "Report, don't just delete", body: "Reporting phishing attempts helps your organization block the sender for everyone else." }
    ]
  });
});

app.listen(PORT, () => {
  console.log(`PhishGuard AI backend listening on port ${PORT}`);
});
