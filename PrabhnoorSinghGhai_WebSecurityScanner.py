"""
Automated Web Security Header & CORS Scanner
============================================
Author : Prabhnoor Singh Ghai
Program: IBM SkillsBuild Cybersecurity Bootcamp 2026 (BharatCares)

What it does
------------
Takes a website address (URL), visits it once, and checks:
  1. Whether important security headers are present and correctly set.
  2. Whether the site leaks technology information (Server, X-Powered-By).
  3. Whether cookies carry the Secure / HttpOnly / SameSite flags.
  4. Whether the site has a risky CORS (Cross-Origin Resource Sharing) setup.
It then prints a PASS / WARN / FAIL report, gives a security score out of 100,
and saves the report to a text file and a JSON file.

IMPORTANT (ethics): Only scan websites you own or have permission to test.
Safe practice targets: https://example.com, https://httpbin.org
This tool only sends ordinary web requests (same as opening a page in a browser).

How to run
----------
    python PrabhnoorSinghGhai_WebSecurityScanner.py
(then type a website address when asked)  OR
    python PrabhnoorSinghGhai_WebSecurityScanner.py https://example.com
"""

import json
import sys
from datetime import datetime

import requests

# ---------------------------------------------------------------------------
# SETTINGS (you can change these)
# ---------------------------------------------------------------------------
TIMEOUT_SECONDS = 10          # how long to wait for a website to answer
TEST_ORIGIN = "https://evil-test-origin.example"   # fake website used for the CORS test

# Each security header: (header name, points, why it matters)
SECURITY_HEADERS = [
    ("Strict-Transport-Security", 20,
     "HSTS forces browsers to use HTTPS only, blocking downgrade and sniffing attacks."),
    ("Content-Security-Policy", 25,
     "CSP controls which scripts/images can load, a strong defence against XSS attacks."),
    ("X-Frame-Options", 15,
     "Stops other sites from showing this page inside a hidden frame (clickjacking)."),
    ("X-Content-Type-Options", 10,
     "Stops the browser from guessing file types (MIME sniffing)."),
    ("Referrer-Policy", 10,
     "Controls how much page address information is shared with other sites."),
    ("Permissions-Policy", 10,
     "Limits browser features such as camera, microphone and location."),
]
# The remaining 10 points come from the CORS and cookie checks (5 each).


# ---------------------------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------------------------
def clean_url(url):
    """Add https:// if the user forgot it."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def make_result(check, status, detail, points_earned, points_possible, advice=""):
    """Store one check result as a small dictionary."""
    return {
        "check": check,
        "status": status,          # PASS, WARN or FAIL
        "detail": detail,
        "points": points_earned,
        "max_points": points_possible,
        "advice": advice,
    }


# ---------------------------------------------------------------------------
# THE CHECKS
# ---------------------------------------------------------------------------
def check_security_headers(headers, url):
    """Check each important security header."""
    results = []
    for name, points, why in SECURITY_HEADERS:
        value = headers.get(name)
        if value is None:
            results.append(make_result(name, "FAIL", "Header is missing.", 0, points, why))
            continue

        # Extra quality checks for some headers
        if name == "Strict-Transport-Security":
            if "max-age" in value.lower():
                try:
                    age = int(value.lower().split("max-age=")[1].split(";")[0].strip())
                except (IndexError, ValueError):
                    age = 0
                if age >= 15552000:      # 180 days
                    results.append(make_result(name, "PASS", f"Present: {value}", points, points))
                else:
                    results.append(make_result(name, "WARN",
                                   f"Present but max-age is short: {value}", points // 2, points,
                                   "Use max-age of at least 15552000 (180 days)."))
            else:
                results.append(make_result(name, "WARN", f"Present but no max-age: {value}",
                                           points // 2, points, why))
        elif name == "Content-Security-Policy":
            csp_tokens = value.lower().replace(";", " ").split()
            if ("'unsafe-inline'" in csp_tokens or "'unsafe-eval'" in csp_tokens
                    or "*" in csp_tokens):
                results.append(make_result(name, "WARN",
                               "Present but uses weak rules (unsafe-inline / unsafe-eval / wildcard).",
                               points // 2, points,
                               "Avoid 'unsafe-inline', 'unsafe-eval' and wildcard sources."))
            else:
                results.append(make_result(name, "PASS", "Present with no obviously weak rules.",
                                           points, points))
        elif name == "X-Frame-Options":
            if value.strip().upper() in ("DENY", "SAMEORIGIN"):
                results.append(make_result(name, "PASS", f"Present: {value}", points, points))
            else:
                results.append(make_result(name, "WARN", f"Unusual value: {value}",
                                           points // 2, points, "Use DENY or SAMEORIGIN."))
        elif name == "X-Content-Type-Options":
            if value.strip().lower() == "nosniff":
                results.append(make_result(name, "PASS", "Present: nosniff", points, points))
            else:
                results.append(make_result(name, "WARN", f"Unusual value: {value}",
                                           points // 2, points, "Set the value to nosniff."))
        else:
            results.append(make_result(name, "PASS", f"Present: {value}", points, points))

    # HTTPS check on the address itself
    if not url.startswith("https://"):
        results.append(make_result("HTTPS in use", "FAIL",
                                   "Site was scanned over plain HTTP (not encrypted).", 0, 0,
                                   "Serve the site over HTTPS."))
    return results


def check_information_leaks(headers):
    """Headers that reveal software names/versions help attackers."""
    results = []
    for name in ("Server", "X-Powered-By"):
        value = headers.get(name)
        if value is None:
            results.append(make_result(name + " (info leak)", "PASS",
                                       "Not shown, which is good.", 0, 0))
        elif any(ch.isdigit() for ch in value):
            results.append(make_result(name + " (info leak)", "WARN",
                           f"Reveals software version: {value}", 0, 0,
                           "Hide version numbers so attackers cannot target known bugs."))
        else:
            results.append(make_result(name + " (info leak)", "PASS",
                                       f"Shown without version: {value}", 0, 0))
    return results


def check_cookies(response):
    """Check Secure / HttpOnly / SameSite flags on cookies."""
    raw_cookies = []
    try:
        raw_cookies = response.raw.headers.getlist("Set-Cookie")
    except AttributeError:
        pass

    if not raw_cookies:
        return [make_result("Cookie flags", "PASS",
                            "No cookies were set on this page (nothing to check).", 5, 5)]

    problems = []
    for cookie in raw_cookies:
        # Split "name=value; Secure; HttpOnly; SameSite=Lax" into its parts.
        # Only the attributes (after the first part) are checked, never the value.
        parts = [p.strip() for p in cookie.split(";")]
        cookie_name = parts[0].split("=")[0]
        attributes = [p.split("=")[0].strip().lower() for p in parts[1:]]
        missing = []
        if "secure" not in attributes:
            missing.append("Secure")
        if "httponly" not in attributes:
            missing.append("HttpOnly")
        if "samesite" not in attributes:
            missing.append("SameSite")
        if missing:
            problems.append(f"{cookie_name}: missing {', '.join(missing)}")

    if problems:
        return [make_result("Cookie flags", "WARN", "; ".join(problems), 2, 5,
                            "Add Secure, HttpOnly and SameSite to every cookie.")]
    return [make_result("Cookie flags", "PASS", "All cookies have Secure, HttpOnly, SameSite.", 5, 5)]


def check_cors(url):
    """
    CORS test: we pretend to be a different website (a fake origin) and see
    whether the target site agrees to share its data with it.
    """
    try:
        r = requests.get(url, headers={"Origin": TEST_ORIGIN}, timeout=TIMEOUT_SECONDS)
    except requests.RequestException as error:
        return [make_result("CORS policy", "WARN", f"Could not run CORS test: {error}", 0, 5)]

    allow_origin = r.headers.get("Access-Control-Allow-Origin")
    allow_creds = r.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"

    if allow_origin is None:
        return [make_result("CORS policy", "PASS",
                            "No cross-origin access granted to unknown websites.", 5, 5)]
    if allow_origin == TEST_ORIGIN and allow_creds:
        return [make_result("CORS policy", "FAIL",
                            "CRITICAL: site reflects any Origin AND allows credentials.", 0, 5,
                            "Only allow a fixed list of trusted origins.")]
    if allow_origin == TEST_ORIGIN:
        return [make_result("CORS policy", "WARN",
                            "Site reflects any Origin we send (trusts every website).", 1, 5,
                            "Only allow a fixed list of trusted origins.")]
    if allow_origin == "*":
        if allow_creds:
            return [make_result("CORS policy", "FAIL",
                                "Wildcard (*) with credentials allowed.", 0, 5,
                                "Never combine * with credentials.")]
        return [make_result("CORS policy", "WARN",
                            "Wildcard (*): any website can read responses.", 2, 5,
                            "Fine for public data only; otherwise restrict origins.")]
    return [make_result("CORS policy", "PASS", f"Restricted to: {allow_origin}", 5, 5)]


# ---------------------------------------------------------------------------
# REPORT
# ---------------------------------------------------------------------------
def grade(score):
    if score >= 90:
        return "A (Excellent)"
    if score >= 75:
        return "B (Good)"
    if score >= 60:
        return "C (Fair)"
    if score >= 40:
        return "D (Poor)"
    return "F (Very weak)"


def build_report(url, results):
    earned = sum(r["points"] for r in results)
    possible = sum(r["max_points"] for r in results)
    score = round(earned * 100 / possible) if possible else 0

    lines = []
    lines.append("=" * 66)
    lines.append("  WEB SECURITY HEADER & CORS SCAN REPORT")
    lines.append("=" * 66)
    lines.append(f"  Target : {url}")
    lines.append(f"  Time   : {datetime.now().strftime('%d %b %Y, %H:%M:%S')}")
    lines.append("-" * 66)
    for r in results:
        lines.append(f"[{r['status']:<4}] {r['check']}")
        lines.append(f"        {r['detail']}")
        if r["status"] != "PASS" and r["advice"]:
            lines.append(f"        Advice: {r['advice']}")
    lines.append("-" * 66)
    passed = sum(1 for r in results if r["status"] == "PASS")
    warned = sum(1 for r in results if r["status"] == "WARN")
    failed = sum(1 for r in results if r["status"] == "FAIL")
    lines.append(f"  PASS: {passed}   WARN: {warned}   FAIL: {failed}")
    lines.append(f"  SECURITY SCORE: {score}/100   GRADE: {grade(score)}")
    lines.append("  Note: simplified self-defined score, not an industry-standard rating.")
    lines.append("=" * 66)
    return "\n".join(lines), score


def scan(url):
    """Run every check on one website and return the report text."""
    url = clean_url(url)
    print(f"\nScanning {url} ...")
    try:
        response = requests.get(url, timeout=TIMEOUT_SECONDS, allow_redirects=True)
    except requests.RequestException as error:
        print(f"Could not connect to the website: {error}")
        return None

    final_url = response.url
    results = []
    results += check_security_headers(response.headers, final_url)
    results += check_information_leaks(response.headers)
    results += check_cookies(response)
    results += check_cors(final_url)

    report_text, score = build_report(final_url, results)
    print(report_text)

    # Save the results to files
    safe_name = final_url.split("//")[1].split("/")[0].replace(":", "_")
    with open(f"scan_report_{safe_name}.txt", "w", encoding="utf-8") as f:
        f.write(report_text)
    with open(f"scan_report_{safe_name}.json", "w", encoding="utf-8") as f:
        json.dump({"url": final_url, "score": score, "results": results}, f, indent=2)
    print(f"Saved: scan_report_{safe_name}.txt and scan_report_{safe_name}.json")
    return report_text


def main():
    print("Web Security Header & CORS Scanner  |  by Prabhnoor Singh Ghai")
    print("Only scan websites you own or have permission to test.")
    if len(sys.argv) > 1:
        targets = sys.argv[1:]
    else:
        text = input("Enter website address(es), separated by spaces "
                     "(e.g. example.com): ")
        targets = text.split()
    if not targets:
        print("No website entered. Please run again.")
        return
    for target in targets:
        scan(target)


if __name__ == "__main__":
    main()
