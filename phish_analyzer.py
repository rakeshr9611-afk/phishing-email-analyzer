#!/usr/bin/env python3
"""
phish_analyzer.py - Phishing Email Analyzer
Author: Rakesh Rajbali

Parses a raw .eml file the way a SOC analyst triages a reported phish:
  * Email authentication results (SPF / DKIM / DMARC)
  * Sender anomalies (From vs Return-Path / Reply-To, display-name spoofing)
  * Lookalike / typosquatted domains of well-known brands
  * URL analysis (text-vs-href mismatch, raw IPs, shorteners, risky TLDs)
  * Dangerous attachments (executables, scripts, macro docs, double extensions)
  * Social-engineering language (urgency, threats, credential requests)
  * IOC extraction (domains, URLs, IPs, attachment SHA-256 hashes)

Produces a 0-100 risk score and verdict. Python standard library only.

Usage:
    python phish_analyzer.py sample_phish_paypal.eml
    python phish_analyzer.py *.eml --json iocs.json
"""
import argparse
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

BRANDS = ["paypal", "microsoft", "office365", "apple", "amazon", "netflix", "google",
          "chase", "wellsfargo", "bankofamerica", "docusign", "dropbox", "linkedin", "stjohns"]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "rb.gy", "cutt.ly"}
RISKY_TLDS = {"xyz", "top", "zip", "mov", "click", "country", "gq", "tk", "ml", "cf", "ru", "support"}
RISKY_EXT = {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".hta", ".iso", ".img",
             ".lnk", ".docm", ".xlsm", ".pptm", ".html", ".htm", ".jar", ".msi", ".one"}
URGENCY = [r"urgent", r"immediately", r"within 24 hours", r"account (?:will be )?(?:suspended|locked|closed)",
           r"verify your (?:account|identity)", r"unusual (?:sign-in|activity)", r"confirm your (?:password|details)",
           r"final notice", r"action required", r"payment (?:failed|declined)", r"click (?:here|below)"]
HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a"})


@dataclass
class Indicator:
    points: int
    category: str
    detail: str


@dataclass
class Report:
    file: str
    subject: str
    from_addr: str
    score: int = 0
    verdict: str = ""
    indicators: list = field(default_factory=list)
    iocs: dict = field(default_factory=dict)


class LinkParser(HTMLParser):
    """Collect (href, visible_text) pairs from HTML bodies."""
    def __init__(self):
        super().__init__()
        self.links, self._href, self._text = [], None, []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def domain_of(addr: str) -> str:
    return parseaddr(addr)[1].rpartition("@")[2].lower().strip(">")


def registrable(domain: str) -> str:
    parts = domain.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def lookalike_brand(domain: str):
    """Return the brand a domain imitates, or None if it's legit/unrelated."""
    reg = registrable(domain)
    label = reg.split(".")[0]
    normalized = label.translate(HOMOGLYPHS).replace("-", "").replace("rn", "m").replace("vv", "w")
    for brand in BRANDS:
        if label == brand:
            return None  # the real brand domain
        if normalized == brand or (brand in normalized and label != brand):
            return brand
        if len(label) >= 5 and levenshtein(normalized, brand) == 1:
            return brand
    return None


def analyze_file(path: str) -> Report:
    with open(path, "rb") as fh:
        msg = BytesParser(policy=policy.default).parse(fh)

    rpt = Report(file=path, subject=str(msg["Subject"] or ""), from_addr=str(msg["From"] or ""))
    add = lambda pts, cat, det: rpt.indicators.append(Indicator(pts, cat, det))

    from_name, from_email = parseaddr(rpt.from_addr)
    from_dom = domain_of(rpt.from_addr)
    domains, urls, ips, hashes = {from_dom}, set(), set(), []

    # 1. Authentication-Results ------------------------------------------
    auth = " ".join(str(h) for h in msg.get_all("Authentication-Results", [])).lower()
    for mech, pts in (("spf", 15), ("dkim", 15), ("dmarc", 20)):
        m = re.search(rf"{mech}=(\w+)", auth)
        result = m.group(1) if m else "none"
        if result != "pass":
            add(pts, "Authentication", f"{mech.upper()} = {result}")

    # 2. Sender anomalies ------------------------------------------------
    for hdr in ("Return-Path", "Reply-To"):
        if msg[hdr]:
            d = domain_of(str(msg[hdr]))
            domains.add(d)
            if d and registrable(d) != registrable(from_dom):
                add(15, "Sender Mismatch", f"{hdr} domain '{d}' differs from From domain '{from_dom}'")
    for brand in BRANDS:
        if brand in from_name.lower().replace(" ", "") and brand not in registrable(from_dom):
            add(20, "Display-Name Spoof", f"Display name '{from_name}' claims {brand} but sent from {from_dom}")
            break
    b = lookalike_brand(from_dom)
    if b:
        add(25, "Lookalike Domain", f"Sender domain '{from_dom}' imitates '{b}'")

    # Originating IP from the bottom-most Received header
    received = msg.get_all("Received", [])
    if received:
        m = re.search(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]", str(received[-1]))
        if m:
            ips.add(m.group(1))

    # 3. Body + URLs -----------------------------------------------------
    text_body, links = "", []
    for part in msg.walk():
        ctype = part.get_content_type()
        if part.get_content_disposition() == "attachment":
            continue
        if ctype == "text/plain":
            text_body += part.get_content()
        elif ctype == "text/html":
            html = part.get_content()
            lp = LinkParser()
            lp.feed(html)
            links += lp.links
            text_body += re.sub(r"<[^>]+>", " ", html)

    urls |= set(re.findall(r"https?://[^\s\"'<>]+", text_body))
    urls -= {t for _, t in links}  # visible link text is the lure, not a real destination
    urls |= {h for h, _ in links if h and h.startswith("http")}

    flagged_hosts = set()
    for href, text in links:
        shown = re.search(r"(?:https?://)?([\w.-]+\.[a-z]{2,})", text or "", re.I)
        real = urlparse(href).hostname or ""
        if shown and real and registrable(shown.group(1)) != registrable(real):
            add(20, "Link Mismatch", f"Link text shows '{shown.group(1)}' but points to '{real}'")

    for u in urls:
        host = (urlparse(u).hostname or "").lower()
        if not host:
            continue
        domains.add(host)
        if host in flagged_hosts:
            continue
        flagged_hosts.add(host)
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
            ips.add(host)
            add(20, "Suspicious URL", f"URL uses raw IP address: {u}")
        if host in SHORTENERS:
            add(10, "Suspicious URL", f"URL shortener hides destination: {u}")
        if host.rsplit(".", 1)[-1] in RISKY_TLDS:
            add(10, "Suspicious URL", f"High-risk TLD: {host}")
        lb = lookalike_brand(host)
        if lb:
            add(25, "Lookalike Domain", f"URL host '{host}' imitates '{lb}'")

    # 4. Social engineering language -------------------------------------
    hits = sorted({m.group(0).lower() for p in URGENCY for m in re.finditer(p, text_body, re.I)})
    if hits:
        add(min(5 * len(hits), 20), "Social Engineering", f"Urgency/pressure phrases: {hits}")

    # 5. Attachments -----------------------------------------------------
    for part in msg.iter_attachments():
        name = part.get_filename() or "unnamed"
        data = part.get_payload(decode=True) or b""
        sha = hashlib.sha256(data).hexdigest()
        hashes.append({"filename": name, "sha256": sha, "size": len(data)})
        lower = name.lower()
        ext = "." + lower.rsplit(".", 1)[-1] if "." in lower else ""
        if re.search(r"\.(pdf|docx?|xlsx?|jpg|png|txt)\.\w+$", lower):
            add(30, "Dangerous Attachment", f"Double extension disguises file type: {name}")
        elif ext in RISKY_EXT:
            add(25, "Dangerous Attachment", f"High-risk attachment type: {name}")

    # Score & verdict ----------------------------------------------------
    rpt.score = min(sum(i.points for i in rpt.indicators), 100)
    rpt.verdict = ("MALICIOUS" if rpt.score >= 70 else "SUSPICIOUS" if rpt.score >= 35 else "LIKELY SAFE")
    rpt.iocs = {"sender": from_email, "domains": sorted(d for d in domains if d),
                "urls": sorted(urls), "ips": sorted(ips), "attachments": hashes}
    return rpt


def print_report(r: Report):
    color = {"MALICIOUS": "\033[91m", "SUSPICIOUS": "\033[93m", "LIKELY SAFE": "\033[92m"}[r.verdict]
    bar = "#" * (r.score // 5) + "-" * (20 - r.score // 5)
    print("=" * 72)
    print(f"File:    {r.file}\nSubject: {r.subject}\nFrom:    {r.from_addr}")
    print(f"Risk:    [{bar}] {r.score}/100  ->  {color}{r.verdict}\033[0m")
    print("-" * 72)
    for i in sorted(r.indicators, key=lambda x: -x.points):
        print(f"  +{i.points:<3} {i.category:<22} {i.detail}")
    if not r.indicators:
        print("  No indicators found.")
    print("\n  IOCs:")
    for k in ("domains", "urls", "ips"):
        if r.iocs[k]:
            print(f"    {k:<8} {', '.join(r.iocs[k])}")
    for a in r.iocs["attachments"]:
        print(f"    file     {a['filename']}  sha256={a['sha256']}")
    print()


def main():
    ap = argparse.ArgumentParser(description="Triage phishing emails (.eml).")
    ap.add_argument("emails", nargs="+")
    ap.add_argument("--json", help="write reports + IOCs as JSON")
    args = ap.parse_args()
    reports = [analyze_file(p) for p in args.emails]
    for r in reports:
        print_report(r)
    if args.json:
        with open(args.json, "w") as fh:
            json.dump([asdict(r) for r in reports], fh, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
