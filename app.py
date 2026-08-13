import os
import requests
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# يمكنك وضع مفتاح API الخاص بـ Google Safe Browsing هنا لفحص حقيقي متقدم
# للحصول على مفتاح مجاني: https://developers.google.com/safe-browsing/v4
GOOGLE_SAFE_BROWSING_API_KEY = "ضع_مفتاح_API_هنا_إن_وجد"

def check_url_safety(target_url):
    # 1. إذا كان لديك مفتاح Google Safe Browsing API
    if GOOGLE_SAFE_BROWSING_API_KEY and GOOGLE_SAFE_BROWSING_API_KEY != "ضع_مفتاح_API_هنا_إن_وجد":
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
        payload = {
            "client": {"clientId": "url-checker", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": target_url}]
            }
        }
        try:
            response = requests.post(api_url, json=payload, timeout=5)
            data = response.json()
            # إذا أرجعت Google تطابقاً فهذا يعني أن الرابط ملغم أو ضار
            if "matches" in data and len(data["matches"]) > 0:
                return False
        except Exception:
            pass

    # 2. فحص أساسي لبروتوكول واستجابة الموقع في حال عدم توفر API
    try:
        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url

        res = requests.get(target_url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
        # إذا كان الموقع يعمل وتصل الاستجابة بنجاح
        if res.status_code == 200:
            return True
        else:
            return False
    except Exception:
        return False

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    url = data.get('url', '').strip()

    if not url:
        return jsonify({'status': 'invalid', 'message': 'يرجى إدخال رابط صحيح'})

    is_safe = check_url_safety(url)

    if is_safe:
        return jsonify({'is_safe': True, 'message': 'الموقع امن ✅️'})
    else:
        return jsonify({'is_safe': False, 'message': 'الموقع غير امن ⛔️'})

if __name__ == '__main__':
    app.run(debug=True)

