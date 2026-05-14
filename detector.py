from virustotal import check_virustotal
import re
import whois
import tldextract

from datetime import datetime
from urllib.parse import urlparse

def check_phishing(url):

    score = 0
    reasons = []

    suspicious_keywords = [
        "login",
        "verify",
        "secure",
        "update",
        "account",
        "banking",
        "confirm",
        "password"
    ]

    suspicious_tlds = [
        "xyz",
        "tk",
        "ml",
        "ga",
        "cf"
    ]

    # Rule 1 — Long URL
    if len(url) > 75:
        score += 1
        reasons.append("URL is too long")

    # Rule 2 — Suspicious keywords
    for word in suspicious_keywords:
        if word in url.lower():
            score += 2
            reasons.append(f"Suspicious keyword: {word}")

    # Rule 3 — @ symbol
    if "@" in url:
        score += 2
        reasons.append("@ symbol detected")

    # Rule 4 — Missing HTTPS
    if not url.startswith("https://"):
        score += 1
        reasons.append("No HTTPS encryption")

    # Rule 5 — IP address
    ip_pattern = r"(\d{1,3}\.){3}\d{1,3}"

    if re.search(ip_pattern, url):
        score += 3
        reasons.append("IP address used")

    # Rule 6 — Too many hyphens
    if url.count("-") > 3:
        score += 1
        reasons.append("Too many hyphens")

    # Rule 7 — Suspicious subdomains
    parsed = urlparse(url)

    if len(parsed.netloc.split(".")) > 3:
        score += 2
        reasons.append("Suspicious subdomain structure")

    # Rule 8 — Suspicious TLD
    extracted = tldextract.extract(url)

    if extracted.suffix in suspicious_tlds:
        score += 2
        reasons.append(f"Suspicious domain extension: .{extracted.suffix}")

    # Rule 9 — WHOIS Domain Age
    try:

        domain_info = whois.whois(url)

        creation_date = domain_info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:

            age = (datetime.now() - creation_date).days

            if age < 180:
                score += 3
                reasons.append("Recently registered domain")

    except:
        score += 2
        reasons.append("WHOIS information unavailable")

    # Rule 10 — VirusTotal Reputation

    malicious, suspicious = check_virustotal(url)

    if malicious > 0:
        score += 5
        reasons.append(f"VirusTotal flagged as malicious ({malicious} engines)")

    if suspicious > 0:
        score += 2
        reasons.append(f"VirusTotal suspicious detection ({suspicious} engines)")

    # Final Decision
    if score >= 7:
        status = "⚠ HIGH RISK PHISHING WEBSITE"

    elif score >= 4:
        status = "⚠ SUSPICIOUS WEBSITE"

    else:
        status = "✅ LEGITIMATE WEBSITE"

    return f"{status} | Risk Score: {score} | Reasons: {', '.join(reasons)}"
