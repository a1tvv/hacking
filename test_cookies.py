#!/usr/bin/env python3
import requests
import urllib3
urllib3.disable_warnings()

# ВСТАВЬ СВОИ COOKIES ИЗ DEVTOOLS
cookies = {
    ".AspNetCore.Cookies": "PASTE_HERE_YOUR_COOKIE",
    # ".AspNetCore.Antiforgery.xxx": "PASTE_HERE_IF_EXISTS",
}

session = requests.Session()
session.cookies.update(cookies)
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
})

endpoints = [
    "https://my.iuca.kg/StudentTranscripts/StudentTranscript",
    "https://my.iuca.kg/StudentTranscripts/StudentEnglishLevelTests",
    "https://my.iuca.kg/Schedules",
    "https://my.iuca.kg/StudentCourseRegistrations/GetStudentCourses",
    "https://my.iuca.kg/trace.axd",
    "https://my.iuca.kg/elmah.axd",
    "https://my.iuca.kg/swagger",
]

for ep in endpoints:
    try:
        r = session.get(ep, timeout=10, verify=False, allow_redirects=False)
        print(f"[{r.status_code}] {ep} ({len(r.content)} bytes)")
        if r.status_code == 200:
            # Сохранить содержимое
            import pathlib
            name = ep.split("/")[-1] or "root"
            pathlib.Path(f"response_{name}.html").write_text(r.text, encoding="utf-8")
    except Exception as e:
        print(f"[ERR] {ep}: {e}")