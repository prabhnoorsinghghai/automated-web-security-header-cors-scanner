# Automated Web Security Header & CORS Scanner

**Author:** Prabhnoor Singh Ghai
**Program:** IBM SkillsBuild Cybersecurity Bootcamp 2026 (BharatCares)
**Project topic:** Automated Web Scanner: a Python script to audit sites for secure headers and CORS flaws

## Project Description
This tool takes a website address, visits it, and checks whether the site is protected with the security settings that modern browsers rely on. It then prints a PASS / WARN / FAIL report with advice on how to fix each problem, and gives an overall **security score out of 100**.

### What it checks
| Check | Why it matters |
|---|---|
| Strict-Transport-Security (HSTS) | Forces HTTPS-only connections |
| Content-Security-Policy (CSP) | Defends against cross-site scripting (XSS) |
| X-Frame-Options | Prevents clickjacking |
| X-Content-Type-Options | Prevents MIME-type sniffing |
| Referrer-Policy | Limits information shared with other sites |
| Permissions-Policy | Restricts camera, microphone, location, etc. |
| Server / X-Powered-By | Detects software version information leaks |
| Cookie flags | Checks Secure, HttpOnly and SameSite |
| CORS policy | Detects sites that trust any origin, or use `*` with credentials |

## Technologies Used
- Python 3.8+
- `requests` library (sends web requests)
- Standard library modules: `json`, `sys`, `datetime`

## Dataset
No external dataset is used. The tool reads live HTTP response headers from the website being scanned. For safe practice, use `https://example.com` or `https://httpbin.org`, or a website you own.

## Setup and Run Instructions
1. Install Python from https://www.python.org/downloads/ (tick "Add Python to PATH").
2. Download or clone this repository and open a terminal in its folder.
3. Install the dependency:
   ```
   pip install -r requirements.txt
   ```
4. Run the scanner:
   ```
   python PrabhnoorSinghGhai_WebSecurityScanner.py
   ```
   Type a website address when asked (for example `example.com`). You can also pass it directly:
   ```
   python PrabhnoorSinghGhai_WebSecurityScanner.py https://example.com
   ```
5. The report appears on screen and is saved as `scan_report_<site>.txt` and `.json`.

## Testing Safely
`test_servers.py` starts a deliberately weak site (port 8081) and a well-protected site (port 8082) on your own computer. Run `python test_servers.py` in one window, then scan `http://127.0.0.1:8081` and `http://127.0.0.1:8082` in another. Expected scores: about 2/100 and 100/100.

## Sample Output (shortened, from a deliberately weak test server)
```
[FAIL] Strict-Transport-Security
        Header is missing.
[FAIL] Content-Security-Policy
        Header is missing.
[WARN] Cookie flags
        session: missing Secure, HttpOnly, SameSite
[FAIL] CORS policy
        CRITICAL: site reflects any Origin AND allows credentials.
  PASS: 0   WARN: 3   FAIL: 8
  SECURITY SCORE: 2/100   GRADE: F (Very weak)
```

## Real Scan Result (example.com, 20 Oct 2026)
All six security headers were missing, no cookies were set, no risky CORS behaviour was found, and the server did not reveal a version number. **Score: 10/100, Grade F.** This is expected, because example.com is a minimal demo page.

## Scoring
Security headers = 90 points, cookie flags = 5, CORS = 5 (scaled to 100 by the points that apply). Grades: A 90+, B 75+, C 60+, D 40+, F below 40. The information-leak checks are informational and carry no points. The score is a simplified, self-defined measure, **not an industry-standard security rating**, and the report is a preliminary audit, not proof that a site is secure or vulnerable.

## Ethical Use Notice
Only scan websites that you own or have written permission to test. The tool sends ordinary web requests only, and it does not exploit or attack anything. It is built for learning and defensive security auditing.

## Limitations and Future Work
- Checks only one page per run (the address given).
- Could be extended to scan many pages, export HTML/PDF reports, or run on a schedule.
