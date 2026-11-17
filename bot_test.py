import html
import re
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

URL = "https://localhost:7279/Account/Login"

s = requests.Session()

def get_words():
    r = s.get(URL, verify=False)
    m = re.search(r'id="captcha-words"[^>]*>\s*<strong>(.*?)</strong>', r.text)
    return [w.strip() for w in m.group(1).split(",")] if m else []

print("Test 1: Bot wypełnia ukryte pole")
words = get_words()
r = s.post(URL, verify=False, data={
    "username": "czytelnik2",
    "password": "ZleHaslo123",
    "captchaAnswer": words[0],
    "website": "http://spam.pl"
})
text = html.unescape(r.text)
print("Wynik:", "Zablokowano (honeypot)" if "ukryte pole" in text else "Przeszło")

print("\nTest 2: Bot podaje błędną CAPTCHA")
words = get_words()
r = s.post(URL, verify=False, data={
    "username": "czytelnik2",
    "password": "DlugieHasloStartowe123!",
    "captchaAnswer": "zle_slowo",
    "website": ""
})
text = html.unescape(r.text)
print("Wynik:", "Zablokowano (błędna CAPTCHA)" if "Błędna odpowiedź CAPTCHA" in text else "Przeszło")

print("\nTest 3: Próba logowania na konto-pułapkę (backup_admin)")
words = get_words()
s.post(URL, verify=False, data={
    "username": "backup_admin",
    "password": "admin123",
    "captchaAnswer": words[0],
    "website": ""
})
print("Wynik: Wysłano żądanie (alert Canarytokens wysłany na e-mail)")

print("\nTest 4: Atak brute-force na konto czytelnik2")
for i in range(1, 25):
    words = get_words()
    guess = words[0]
    r = s.post(URL, verify=False, data={
        "username": "czytelnik2",
        "password": f"ZleHaslo_{i}",
        "captchaAnswer": guess,
        "website": ""
    })
    text = html.unescape(r.text)
    if "zablokowane" in text.lower():
        print(f"Próba {i}: Konto zablokowane na 15 minut")
        break
    elif "Login lub hasło niepoprawne" in text:
        print(f"Próba {i}: Trafiono CAPTCHA, ale błędne hasło")
    else:
        print(f"Próba {i}: Błędna CAPTCHA")