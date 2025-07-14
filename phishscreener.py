import streamlit as st
import requests
import re
from urllib.parse import urlparse
import socket
import ssl
import whois

# ---------- CONFIG ----------
st.set_page_config(page_title="PhishScreener", layout="centered")

# ---------- CUSTOM STYLES ----------
st.markdown("""
<style>
/* Page background */
[data-testid="stAppViewContainer"] {
    background-color: #f0f8ff;
}

/* General text */
html, body, [class*="css"] {
    color: #000 !important;
    font-family: 'Noto Nastaliq Urdu', 'Segoe UI', sans-serif !important;
}

/* Headings */
h1, h2, h3, h4 {
    color: #006400 !important;
}

/* Expanders */
div[data-testid="stExpander"] > details {
    background-color: #e6f2ff !important;
    border: 1px solid #cce5ff;
    border-radius: 6px;
    padding: 8px;
    margin-bottom: 10px;
}

/* Buttons */
button[kind="primary"], .stButton>button {
    background-color: #006400 !important;
    color: white !important;
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: bold;
}
</style>
""", unsafe_allow_html=True)

# ---------- LANGUAGE SELECTION ----------
language = st.radio("Select Language", ["English", "اردو"])
rtl = language == "اردو"

# ---------- QURAN ----------
st.markdown("""
<div style='text-align: center; direction: rtl; font-size: 22px;'>
<b>﴿ يَا أَيُّهَا الَّذِينَ آمَنُوا إِن جَاءَكُمْ فَاسِقٌۭ بِنَبَإٍۢ فَتَبَيَّنُوا ﴾</b><br>
<i>"اے ایمان والو! اگر کوئی فاسق تمہارے پاس کوئی خبر لے کر آئے تو تحقیق کر لیا کرو"</i><br>
<span>سورۃ الحجرات، آیت ٦</span>
</div>
""", unsafe_allow_html=True)

st.title("🎣 PhishScreener")

# ---------- SAFETY TIPS ----------
if language == "English":
    st.markdown("""
    ### Always Remember!
    - Government officials **never** ask for money transfers over the phone.
    - Job offers requiring **upfront payments** are usually scams.
    - Avoid sharing **CNIC, family, or banking details** with unverified sources.
    - **Urgent calls to action** (e.g. "click now", "transfer quickly") are suspicious.
    - Check for **brand impersonation** in URLs or email addresses.
    """)
else:
    st.markdown("""
    <div style='text-align: right; direction: rtl;'>
    <h4>یاد رکھیں:</h4>
    <ul>
    <li>ایسی ویب سائٹس پر اعتبار نہ کریں جو فوراً پیسے مانگیں۔</li>
    <li>"جلدی کلک کریں" یا "ابھی ادائیگی کریں" والے پیغام اکثر فراڈ ہوتے ہیں۔</li>
    <li>آن لائن نوکری کی آفر اگر پیسے مانگے تو وہ جعلی ہو سکتی ہے۔</li>
    <li>مشکوک ویب سائٹس پر اپنی شناختی، بینک یا ذاتی معلومات نہ دیں۔</li>
    <li>ویب لنک اور برانڈ کا ہجے غور سے چیک کریں — یہ جعلی بھی ہو سکتا ہے۔</li>
    </ul>
    </div>
    """, unsafe_allow_html=True)

# ---------- READ BEFORE SCANNING ----------
if language == "English":
    with st.expander("ℹ️ Read Before Scanning"):
        st.markdown("""
        - **PhishScreener** helps identify websites that might be unsafe, suspicious, or malicious.
        - Use **Basic Scan** to quickly assess a URL based on its structure and naming patterns.
        - Use **Advanced Scan** for deeper analysis using threat feeds and site content.
        - Only **public information** is analyzed—your input is never stored.
        - This tool cannot *guarantee* safety but highlights **visible red flags**.
        """)
else:
    with st.expander("اسکین شروع کرنے سے پہلے پڑھیں"):
        st.markdown("""
        <div style='text-align: right; direction: rtl;'>
        <ul>
        <li><b>فِش اسکرینر</b> آپ کی مدد کرتا ہے ایسی ویب سائٹس کی شناخت میں جو غیر محفوظ، مشکوک یا خطرناک ہو سکتی ہیں۔</li>
        <li><b>بیسک اسکین</b> کے ذریعے لنک کا نام اور ساخت دیکھ کر فوری اندازہ لگایا جاتا ہے۔</li>
        <li><b>ایڈوانس اسکین</b> میں تھریٹ فیڈز اور ویب سائٹ کے مواد کی بنیاد پر گہرا تجزیہ کیا جاتا ہے۔</li>
        <li>صرف عوامی معلومات کا تجزیہ کیا جاتا ہے — آپ کا دیا گیا ڈیٹا کہیں محفوظ نہیں کیا جاتا۔</li>
        <li>یہ ٹول مکمل تحفظ کی ضمانت نہیں دیتا، مگر واضح خطرات کی نشان دہی ضرور کرتا ہے۔</li>
        </ul>
        </div>
        """, unsafe_allow_html=True)

# ---------- TOOL DESCRIPTION ----------
if language == "English":
    st.write("Check if a website is safe, suspicious, or potentially dangerous.")
else:
    st.markdown("""
    <div style='text-align: right; direction: rtl;'>
    جانیے کہ آیا ویب سائٹ محفوظ، مشکوک یا خطرناک ہے۔<br>
    ویب سائٹ چیک کرنے کے لیے نیچے دی گئی جگہ پر لنک درج کریں۔
    </div>
    """, unsafe_allow_html=True)

if "scan_count" not in st.session_state:
    st.session_state.scan_count = 0

# ---------- USER INPUT ----------
input_value = st.text_input("🔗 Enter Website URL", placeholder="https://example.com")
scan_mode = st.radio("🧪 Choose scan depth", ["Basic", "Advanced"], horizontal=False)

# ---------- DATA ----------
FAMOUS_DOMAINS = ['google.com', 'facebook.com', 'microsoft.com', 'apple.com', 'amazon.com', 'netflix.com', 'paypal.com', 'yahoo.com', 'outlook.com']
SUSPICIOUS_WORDS = [
    'login', 'signin', 'secure', 'update', 'verify', 'auth', 'account',
    'alert', 'suspended', 'support', 'password', 'validate', 'confirm', 'billing', 'reset', 'banking', 'security', 'unusual', 'warning'
]
FAKE_BRANDS = ['goog1e', 'paypa1', 'micr0soft', 'faceb00k', 'app1e', 'netfl1x', 'amazan', 'yaho0', 'out1ook']
SUSPICIOUS_TLDS = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club', 'fit', 'buzz', 'click']
MALICIOUS_KEYWORDS = ['verify your account', 'confirm password', 'banking alert', 'update payment', 'login here', 'you have won', 'click here to claim', 'free iphone']

# ---------- HELPERS ----------
def extract_domain(url):
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower() if parsed.netloc else parsed.path.lower()
    except:
        return url

def clean_domain(text):
    text = text.strip().lower()
    text = text.replace("http://", "").replace("https://", "")
    return text.split("/")[0]

def check_dns(domain):
    try:
        ip = socket.gethostbyname(domain)
        if ip.startswith("127.") or ip == "0.0.0.0":
            return None
        return ip
    except:
        return None

def check_http(domain):
    try:
        if not domain.startswith("http"):
            domain = "http://" + domain
        resp = requests.get(domain, timeout=5)
        return True if resp.status_code < 400 else False
    except:
        return False

def check_ssl(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
        issuer = dict(x[0] for x in cert['issuer'])
        ca = issuer.get('organizationName', 'Unknown')
        return True if cert else False, ca
    except:
        return False, None

def get_domain_age(domain):
    try:
        w = whois.whois(domain)
        return w.creation_date
    except:
        return None

def scan_malicious_content(domain):
    try:
        url = domain if domain.startswith("http") else "http://" + domain
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            content = response.text.lower()
            found = [kw for kw in MALICIOUS_KEYWORDS if kw in content]
            return found
    except:
        return []
    return []

# ---------- HEURISTIC CHECK ----------
def is_suspicious_url(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower() if parsed.netloc else parsed.path.lower()
    path = parsed.path.lower()
    tld = domain.split('.')[-1] if '.' in domain else ''
    matches = []

    if domain not in FAMOUS_DOMAINS:
        for word in SUSPICIOUS_WORDS + FAKE_BRANDS:
            if word in domain or word in path:
                matches.append(word)

    for legit in FAMOUS_DOMAINS:
        if legit not in domain and sum(a == b for a, b in zip(legit, domain)) >= len(legit) - 2:
            matches.append(f"similar-to:{legit}")

    if tld in SUSPICIOUS_TLDS:
        matches.append(f"tld:{tld}")
    return matches

# ---------- THREAT FEED CHECK ----------
def check_threat_feeds(item, feed_list):
    domain_to_check = extract_domain(item)
    matched_feeds = []
    try:
        for feed in feed_list:
            resp = requests.get(feed, timeout=30)
            if resp.status_code == 200:
                lines = resp.text.splitlines()
                for line in lines:
                    if clean_domain(line) == domain_to_check:
                        matched_feeds.append(feed)
                        break
    except:
        pass
    return matched_feeds

# ---------- FEED LISTS ----------
URL_FEEDS = [
    "https://openphish.com/feed.txt",
    "https://data.phishtank.com/data/online-valid.csv",
    "https://phishunt.io/feed.txt",
    "https://urlhaus.abuse.ch/downloads/csv_recent/",
    "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "https://www.botvrij.eu/data/feed-osint/",
    "https://www.circl.lu/doc/misp/feed-osint/",
    "https://www.stopforumspam.com/downloads"
]

# ---------- SCAN ----------
if st.button("Scan"):
    if not input_value:
        st.warning("Please enter a valid website URL.")
    else:
        st.session_state.scan_count += 1
        domain = extract_domain(input_value)

        ip_resolved = check_dns(domain)
        is_http_ok = check_http(domain) if ip_resolved else False
        ssl_ok, ca_issuer = check_ssl(domain) if ip_resolved else (False, None)
        domain_age = get_domain_age(domain) if ip_resolved else None

        heuristics = is_suspicious_url(input_value)
        matched_feeds = check_threat_feeds(input_value, URL_FEEDS) if scan_mode == "Advanced" else []
        malicious_signs = scan_malicious_content(domain) if scan_mode == "Advanced" and ip_resolved else []

        # USER-FACING SIMPLE OUTPUT
        if not ip_resolved:
            st.error("❌ Website not reachable or does not exist.")
        elif heuristics or matched_feeds or malicious_signs:
            st.warning("⚠️ This website appears suspicious. Be cautious.")
        else:
            st.success("🟢 This website appears safe.")

        # OPTIONAL TECHNICAL DETAILS
        if scan_mode == "Advanced" and ip_resolved:
            with st.expander("📄 Technical Details"):
                st.markdown(f"- **Domain Live:** {'✅' if ip_resolved else '❌'}")
                st.markdown(f"- **HTTP Accessible:** {'✅' if is_http_ok else '❌'}")
                st.markdown(f"- **SSL Certificate Detected:** {'✅' if ssl_ok else '❌'}")
                if ca_issuer:
                    st.markdown(f"- **Certificate Authority (CA):** {ca_issuer}")
                if domain_age:
                    st.markdown(f"- **Domain Registered Since:** {domain_age}")
                st.markdown(f"- **Suspicious Elements:** {', '.join(heuristics) if heuristics else 'None'}")
                st.markdown(f"- **Malicious Content:** {'None detected' if not malicious_signs else ', '.join(malicious_signs)}")
                st.markdown(f"- **Blacklisted:** {'⚠️ Found in threat intelligence feed' if matched_feeds else 'Not Blacklisted'}")
                if matched_feeds:
                    st.markdown("- **Threat Feeds Matched:**")
                    for feed in matched_feeds:
                        st.markdown(f"   - {feed}")

if language == "English":
    st.markdown("""
    <hr style="margin-top: 30px; margin-bottom: 10px;"/>
    <div style='text-align: center; font-size: 16px;'>
    🔐 Need security awareness training for your team?<br>
    📞 <a href='https://nidawaqas.com/contact' target='_blank'>Contact Us Here</a>
    </div>
    """, unsafe_allow_html=True)
else:
    st.markdown("""
    <hr style="margin-top: 30px; margin-bottom: 10px;"/>
    <div style='text-align: center; font-size: 16px; direction: rtl;'>
    🔐 اپنی ٹیم کے لیے سیکیورٹی آگاہی ٹریننگ درکار ہے؟<br>
    📞 <a href='https://nidawaqas.com/contact' target='_blank'>ہم سے رابطہ کریں</a>
    </div>
    """, unsafe_allow_html=True)

