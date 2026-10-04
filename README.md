# Phishing Email Analyzer 🎣

A Python tool that triages suspicious emails (`.eml`) the way a SOC analyst handles a user-reported phish: it checks email authentication, sender anomalies, lookalike domains, deceptive links, dangerous attachments and social-engineering language, then outputs a **0–100 risk score**, a verdict and an **IOC list** ready for blocking.

![Python](https://img.shields.io/badge/Python-3.9+-blue) ![Dependencies](https://img.shields.io/badge/dependencies-stdlib%20only-lightgrey) ![Tests](https://img.shields.io/badge/tests-10%20passing-brightgreen)

## Checks performed

| Area | What it looks for | Weight |
|---|---|---|
| **Authentication** | SPF, DKIM, DMARC results from `Authentication-Results` (anything but `pass`) | 15 / 15 / 20 |
| **Sender anomalies** | `Return-Path` / `Reply-To` domain ≠ `From` domain; display name claims a brand the domain doesn't own | 15–20 |
| **Lookalike domains** | Typosquats & homoglyphs of 14 common brands (`paypa1`, `d0cusign`, `arnazon`) via character normalization + Levenshtein distance | 25 |
| **Links** | Visible link text ≠ real destination, raw-IP URLs, URL shorteners, high-risk TLDs (`.xyz`, `.top`, `.click`…) | 10–20 |
| **Attachments** | Double extensions (`.pdf.exe`), executables, scripts, HTML smuggling, macro docs, ISO/LNK; SHA-256 hashed | 25–30 |
| **Language** | Urgency / threat phrases ("account will be suspended", "within 24 hours") | up to 20 |

**Verdict:** `≥70 MALICIOUS` · `35–69 SUSPICIOUS` · `<35 LIKELY SAFE`

## Lab samples

`generate_samples.py` creates three synthetic emails (RFC 5737 IPs, harmless payloads):

| Sample | Scenario | Score | Verdict |
|---|---|---|---|
| `sample_phish_paypal.eml` | Credential harvest: lookalike sender, spoofed link, IP-hosted login page, bit.ly | 100 | 🔴 MALICIOUS |
| `sample_malware_invoice.eml` | Malware delivery: fake DocuSign invoice with `Invoice.pdf.exe` + HTML attachment | 100 | 🔴 MALICIOUS |
| `sample_legit_github.eml` | Real-looking GitHub notification that passes SPF/DKIM/DMARC (control) | 0 | 🟢 LIKELY SAFE |

The control sample matters: a detector that flags everything is useless, so the tests also verify **zero false positives** on legitimate mail.

## Quick start

```bash
python generate_samples.py
python phish_analyzer.py sample_phish_paypal.eml sample_malware_invoice.eml sample_legit_github.eml --json iocs.json
pip install pytest && pytest -q        # 10 tests
```

Analyze your own: in Gmail use **⋮ → Download message**, in Outlook **File → Save As (.eml)**.

## Example output

```
File:    sample_phish_paypal.eml
Subject: Action Required: Your account will be suspended
From:    PayPal Security <service@paypa1-secure.xyz>
Risk:    [####################] 100/100  ->  MALICIOUS
------------------------------------------------------------------------
  +25  Lookalike Domain       Sender domain 'paypa1-secure.xyz' imitates 'paypal'
  +20  Authentication         DMARC = fail
  +20  Display-Name Spoof     Display name 'PayPal Security' claims paypal but sent from paypa1-secure.xyz
  +20  Link Mismatch          Link text shows 'www.paypal.com' but points to 'paypa1-secure.xyz'
  +20  Suspicious URL         URL uses raw IP address: http://198.51.100.23/paypal/login.php
  +15  Sender Mismatch        Reply-To domain 'account-verify-help.top' differs from From domain
  ...
  IOCs:
    domains  198.51.100.23, account-verify-help.top, bit.ly, mailer-xq7.ru, paypa1-secure.xyz
    ips      198.51.100.23, 203.0.113.45
```

Full output: [`sample_output.txt`](sample_output.txt) — add `--json iocs.json` to export IOCs for blocklists.

## Incident response playbook (what an analyst does next)

1. **Block IOCs** — add sender domains, URLs and IPs to the email gateway / web proxy blocklist; add attachment hashes to EDR.
2. **Scope** — search the mail logs for other recipients of the same sender/subject and pull them from inboxes.
3. **Check for clicks** — review proxy/DNS logs for the extracted domains; anyone who clicked gets a password reset + MFA review.
4. **Report** — submit the lookalike domains for takedown and the hashes to VirusTotal.
5. **Educate** — use the sample as a phishing-awareness example ("hover before you click").

## Skills demonstrated

Email header analysis · SPF/DKIM/DMARC · phishing TTPs (MITRE ATT&CK T1566.001/.002) · IOC extraction · Python (stdlib `email`, `html.parser`, `hashlib`) · risk scoring · unit testing

## Roadmap

- [ ] VirusTotal / URLScan.io enrichment for URLs and hashes
- [ ] WHOIS domain-age check (newly registered domains)
- [ ] Batch mode for an entire phishing mailbox export

---
**Author:** Rakesh Rajbali · Cybersecurity, St. John's University
