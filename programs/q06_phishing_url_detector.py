"""Q6 - Detect phishing URLs using common indicators."""
import re
from urllib.parse import urlparse
SUSPICIOUS = ["login", "verify", "secure", "update", "account", "bank", "paypal", "confirm", "password"]
SHORTENERS = ["bit.ly", "tinyurl.com", "goo.gl", "t.co"]
def analyze(url):
    p = urlparse(url if "//" in url else "http://" + url)
    host, flags = p.hostname or "", []
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host): flags.append("IP-based domain")
    if host.count(".") >= 4: flags.append("excessive subdomains")
    if "@" in url: flags.append("'@' in URL")
    if "-" in host: flags.append("hyphenated domain")
    if len(url) > 75: flags.append("very long URL")
    if p.scheme != "https": flags.append("no HTTPS")
    if any(k in url.lower() for k in SUSPICIOUS): flags.append("suspicious keyword")
    if host in SHORTENERS: flags.append("URL shortener")
    return flags
urls = ["https://www.google.com/search?q=python",
        "http://192.168.10.5/secure/login/verify-account",
        "http://secure-paypal.account.verify.update.example-login.com/confirm",
        "https://github.com/anthropics"]
for u in urls:
    f = analyze(u); verdict = "PHISHING" if len(f) >= 3 else "SUSPICIOUS" if f else "SAFE"
    print(f"{verdict:<10} {u}\n           indicators: {f or 'none'}\n")
