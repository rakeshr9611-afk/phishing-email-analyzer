#!/usr/bin/env python3
"""
generate_samples.py
Creates three realistic, fully synthetic .eml samples for the lab:
  1. sample_phish_paypal.eml     - credential-harvesting phish (lookalike domain)
  2. sample_malware_invoice.eml  - malware delivery via disguised attachment
  3. sample_legit_github.eml     - legitimate notification (control sample)

All IPs use RFC 5737 documentation ranges; payloads are harmless text.
"""
from email.message import EmailMessage


def save(msg, name):
    with open(name, "wb") as fh:
        fh.write(bytes(msg))
    print(f"[+] wrote {name}")


# 1. Credential phish -----------------------------------------------------
m = EmailMessage()
m["Received"] = "from mail.paypa1-secure.xyz (unknown [203.0.113.45]) by mx.example.edu"
m["Authentication-Results"] = "mx.example.edu; spf=fail smtp.mailfrom=paypa1-secure.xyz; dkim=none; dmarc=fail"
m["From"] = '"PayPal Security" <service@paypa1-secure.xyz>'
m["Reply-To"] = "support@account-verify-help.top"
m["Return-Path"] = "<bounce@mailer-xq7.ru>"
m["To"] = "student@example.edu"
m["Subject"] = "Action Required: Your account will be suspended"
m.set_content("Unusual sign-in activity detected. Verify your account within 24 hours: "
              "http://198.51.100.23/paypal/login.php")
m.add_alternative("""\
<html><body>
<p>Dear Customer,</p>
<p>We detected <b>unusual sign-in activity</b> on your PayPal account. Your account will be suspended
unless you verify your identity <b>within 24 hours</b>.</p>
<p><a href="http://paypa1-secure.xyz/signin?id=88213">https://www.paypal.com/signin</a></p>
<p>If the link above does not work, click here: <a href="https://bit.ly/3xPhish">Secure Login</a></p>
<p>Thank you,<br>PayPal Security Team</p>
</body></html>
""", subtype="html")
save(m, "sample_phish_paypal.eml")

# 2. Malware invoice ------------------------------------------------------
m = EmailMessage()
m["Received"] = "from smtp.invoices-docusign.click (unknown [203.0.113.99]) by mx.example.edu"
m["Authentication-Results"] = "mx.example.edu; spf=softfail; dkim=fail; dmarc=fail"
m["From"] = '"DocuSign Billing" <billing@d0cusign-invoices.click>'
m["Return-Path"] = "<billing@d0cusign-invoices.click>"
m["To"] = "accounts@example.com"
m["Subject"] = "FINAL NOTICE: Invoice #INV-20931 payment failed"
m.set_content("Hello,\n\nYour payment failed. Please review the attached invoice immediately "
              "to avoid late fees.\n\nRegards,\nBilling Dept")
m.add_attachment(b"MZ-this-is-a-harmless-lab-placeholder-not-real-malware",
                 maintype="application", subtype="octet-stream", filename="Invoice_INV-20931.pdf.exe")
m.add_attachment(b"<html><script>/* harmless lab placeholder */</script></html>",
                 maintype="text", subtype="html", filename="payment_portal.html")
save(m, "sample_malware_invoice.eml")

# 3. Legitimate control ---------------------------------------------------
m = EmailMessage()
m["Received"] = "from out-21.smtp.github.com (out-21.smtp.github.com [192.0.2.21]) by mx.example.edu"
m["Authentication-Results"] = "mx.example.edu; spf=pass smtp.mailfrom=github.com; dkim=pass header.d=github.com; dmarc=pass"
m["From"] = "GitHub <noreply@github.com>"
m["Return-Path"] = "<noreply@github.com>"
m["To"] = "student@example.edu"
m["Subject"] = "[GitHub] A new SSH key was added to your account"
m.set_content("Hey there,\n\nA new public key was added to your account. If you added this key, "
              "no action is needed.\n\nReview your keys: https://github.com/settings/keys\n\nThanks,\nThe GitHub Team")
save(m, "sample_legit_github.eml")
