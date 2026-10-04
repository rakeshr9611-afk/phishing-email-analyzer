import subprocess
import sys
from pathlib import Path

import pytest

import phish_analyzer as pa

HERE = Path(__file__).parent


@pytest.fixture(scope="session", autouse=True)
def samples():
    if not (HERE / "sample_phish_paypal.eml").exists():
        subprocess.run([sys.executable, "generate_samples.py"], cwd=HERE, check=True)


def cats(r):
    return {i.category for i in r.indicators}


def test_paypal_phish_is_malicious():
    r = pa.analyze_file(str(HERE / "sample_phish_paypal.eml"))
    assert r.verdict == "MALICIOUS"
    assert {"Lookalike Domain", "Link Mismatch", "Authentication", "Sender Mismatch"} <= cats(r)
    assert "203.0.113.45" in r.iocs["ips"]
    assert "www.paypal.com" not in r.iocs["domains"]  # lure text is not an IOC


def test_invoice_attachments_flagged():
    r = pa.analyze_file(str(HERE / "sample_malware_invoice.eml"))
    assert r.verdict == "MALICIOUS"
    details = " ".join(i.detail for i in r.indicators)
    assert "Double extension" in details and "payment_portal.html" in details
    assert len(r.iocs["attachments"]) == 2
    assert all(len(a["sha256"]) == 64 for a in r.iocs["attachments"])


def test_legit_email_is_safe():
    r = pa.analyze_file(str(HERE / "sample_legit_github.eml"))
    assert r.verdict == "LIKELY SAFE" and r.score == 0


@pytest.mark.parametrize("domain,brand", [
    ("paypa1.com", "paypal"), ("micros0ft-login.net", "microsoft"),
    ("arnazon.com", "amazon"), ("amazon.com", None), ("github.com", None),
    ("netfllx.com", "netflix"),
])
def test_lookalike(domain, brand):
    assert pa.lookalike_brand(domain) == brand


def test_levenshtein():
    assert pa.levenshtein("paypal", "paypa1") == 1
    assert pa.levenshtein("abc", "abc") == 0
