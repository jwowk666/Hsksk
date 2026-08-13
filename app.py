import urllib.parse
import requests
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

def check_url_safety(target_url):
    try:
        # 1. إكمال الرابط إذا كان مدخلاً بدون http/https
        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url

        # 2. ترميز الرابط بشكل صحيح حتى يتقبل الحروف العربية
        parsed = urllib.parse.urlparse(target_url)
        encoded_path = urllib.parse.quote(parsed.path)
        encoded_query = urllib.parse.quote(parsed.query, safe='=&')
        
        # إعادة بناء الرابط النهائي المعالج
        clean_url = urllib.parse.urlunparse((
            parsed.scheme,
            parsed.netloc,
            encoded_path,
            parsed.params,
            encoded_query,
            parsed.fragment
        ))

        # 3. محاكاة متصفح حقيقي (User-Agent) للالتفاف على حظر البوتات
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'ar,en-US;q=0.7,en;q=0.3'
        }

        # 4. طلب فتح الموقع ومعالجة شهادات SSL
        # verify=False للتأكد من عدم رفض مواقع SSL الخاصة بتشفير معين، مع إتاحة التحويلات تلقائياً (allow_redirects=True)
        res = requests.get(clean_url, headers=headers, timeout=8, verify=False, allow_redirects=True)
        
        # إذا كانت الاستجابة بين 200 و 399، فالموقع يعمل وآمن
        if res.status_code < 400:
            return True
        else:
            return False

    except Exception as e:
        # إذا فشل الاتصال تماماً (مثل دُومين غير موجود)
        return False

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    url = data.get('url', '').strip()

    if not url:
        return jsonify({'is_safe': False, 'message': 'الموقع غير امن ⛔️'})

    is_safe = check_url_safety(url)

    if is_safe:
        return jsonify({'is_safe': True, 'message': 'الموقع امن ✅️'})
    else:
        return jsonify({'is_safe': False, 'message': 'الموقع غير امن ⛔️'})

if __name__ == '__main__':
    app.run(debug=True)
