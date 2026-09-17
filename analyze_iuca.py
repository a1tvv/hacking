#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
analyze_iuca.py — Анализ frontend'а my.iuca.kg
Запускать ТОЛЬКО после получения письменного разрешения.
"""

import requests
import re
import json
from pathlib import Path
from urllib.parse import urljoin

TARGET = "https://my.iuca.kg"
OUT = Path("iuca_analysis")
OUT.mkdir(exist_ok=True)

session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"})

# Отключаем проверку SSL (сайт может иметь самоподписанный серт)
session.verify = False
import urllib3
urllib3.disable_warnings()

def log(msg):
    print(f"[*] {msg}")

def save(name, data):
    p = OUT / name
    with open(p, "w", encoding="utf-8") as f:
        f.write(data if isinstance(data, str) else json.dumps(data, indent=2, ensure_ascii=False))
    log(f"Saved -> {p}")

# 1. Скачать главную
log("Fetching main page...")
r = session.get(TARGET, timeout=15)
save("index.html", r.text)

# 2. Найти все JS-файлы
js_urls = re.findall(r'src="([^"]+\.js[^"]*)"', r.text)
log(f"Found {len(js_urls)} JS files")
for js in js_urls:
    full = urljoin(TARGET, js)
    name = js.split("/")[-1].split("?")[0]
    log(f"Downloading {full}")
    try:
        rr = session.get(full, timeout=15)
        save(name, rr.text)
        # Ищем интересное
        interesting = re.findall(r'["\'](https?://[^"\']+|/[a-zA-Z0-9_\-/]+)["\']', rr.text)
        save(f"{name}.urls.txt", "\n".join(sorted(set(interesting))))
    except Exception as e:
        log(f"Failed: {e}")

# 3. Найти все endpoints в HTML
endpoints = re.findall(r'href="(/[^"]+)"', r.text)
save("endpoints.txt", "\n".join(sorted(set(endpoints))))

# 4. Проверить стандартные ASP.NET endpoints
asp_endpoints = [
    "/.well-known/openid-configuration",
    "/signin-google",
    "/signin-oidc",
    "/Account/Login",
    "/Account/Register",
    "/Account/GoogleLogin",
    "/Account/Logout",
    "/Account/AccessDenied",
    "/Home/Error",
    "/trace.axd",
    "/elmah.axd",
    "/web.config",
    "/global.asax",
    "/api",
    "/api/v1",
    "/api/users",
    "/swagger",
    "/swagger/index.html",
    "/health",
    "/healthz",
    "/metrics",
]

results = {}
for ep in asp_endpoints:
    url = urljoin(TARGET, ep)
    try:
        rr = session.get(url, timeout=10, allow_redirects=False)
        results[ep] = {"status": rr.status_code, "len": len(rr.content), "headers": dict(rr.headers)}
        log(f"{rr.status_code} -> {url}")
        if rr.status_code == 200:
            save(f"ep_{ep.replace('/', '_')}.html", rr.text)
    except Exception as e:
        results[ep] = {"error": str(e)}
        log(f"ERR -> {url}: {e}")

save("asp_endpoints.json", results)

# 5. Проверить OAuth redirect
log("Checking OAuth flow...")
try:
    rr = session.get(f"{TARGET}/Account/GoogleLogin", timeout=10, allow_redirects=False)
    if "Location" in rr.headers:
        loc = rr.headers["Location"]
        log(f"OAuth redirect: {loc}")
        save("oauth_redirect.txt", loc)
        # Парсим параметры
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(loc)
        params = parse_qs(parsed.query)
        save("oauth_params.json", {k: v[0] for k, v in params.items()})
except Exception as e:
    log(f"OAuth check failed: {e}")

log("DONE. Check iuca_analysis/")