"""
fix_url_model.py
Retrain the URL classifier with a BALANCED dataset of safe + phishing URLs.
The previous model was biased because it was trained only on URLs extracted
from phishing emails (even the "safe" labelled rows rarely had URLs, so the
model effectively learned "URL present → phishing").
"""
import os, joblib, re
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.model_selection import train_test_split

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, 'models')
PROCESSED_DIR = os.path.join(BASE_DIR, 'processed')

print("=" * 60)
print("FIXING URL PHISHING MODEL (balanced dataset)")
print("=" * 60)

# ── 1. KNOWN-SAFE URLS (manually curated, covering realistic email links) ──
SAFE_URLS = [
    # Search & productivity
    "https://www.google.com",
    "https://google.com/search?q=example",
    "https://mail.google.com",
    "https://drive.google.com",
    "https://docs.google.com",
    "https://www.youtube.com",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://www.microsoft.com",
    "https://www.office.com",
    "https://outlook.office.com",
    "https://login.microsoftonline.com",
    "https://www.apple.com",
    "https://support.apple.com",
    "https://www.amazon.com",
    "https://www.amazon.in",
    "https://www.linkedin.com",
    "https://www.linkedin.com/in/profile",
    "https://www.facebook.com",
    "https://www.twitter.com",
    "https://www.instagram.com",
    "https://github.com",
    "https://github.com/user/repo",
    "https://stackoverflow.com",
    "https://www.wikipedia.org",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://www.dropbox.com",
    "https://www.paypal.com",
    "https://www.paypal.com/myaccount",
    "https://www.netflix.com",
    "https://www.spotify.com",
    "https://zoom.us/j/meeting",
    "https://meet.google.com/abc-def-ghi",
    "https://www.naukri.com",
    "https://www.indeed.com",
    "https://www.glassdoor.com",
    "https://www.coursera.org",
    "https://www.udemy.com",
    "https://www.medium.com",
    "https://www.reddit.com",
    "https://news.ycombinator.com",
    "https://www.twitch.tv",
    "https://www.slack.com",
    "https://slack.com/app_redirect",
    "https://trello.com",
    "https://www.notion.so",
    "https://www.figma.com",
    "https://www.canva.com",
    "https://www.cloudflare.com",
    "https://www.aws.amazon.com",
    "https://portal.azure.com",
    "https://console.cloud.google.com",
    "https://www.heroku.com",
    "https://www.digitalocean.com",
    "https://www.stripe.com",
    "https://www.shopify.com",
    "https://www.wordpress.com",
    "https://www.wix.com",
    "https://www.squarespace.com",
    "https://www.hubspot.com",
    "https://www.salesforce.com",
    "https://www.zendesk.com",
    "https://www.intercom.com",
    "https://www.mailchimp.com",
    "https://www.sendgrid.com",
    "https://www.twilio.com",
    "https://www.docusign.com",
    "https://www.adobe.com",
    "https://www.typeform.com",
    "https://forms.google.com",
    "https://www.surveymonkey.com",
    "https://www.eventbrite.com",
    "https://www.meetup.com",
    "https://www.booking.com",
    "https://www.airbnb.com",
    "https://www.tripadvisor.com",
    "https://www.expedia.com",
    "https://www.flipkart.com",
    "https://www.myntra.com",
    "https://www.zomato.com",
    "https://www.swiggy.com",
    "https://www.ola.com",
    "https://www.uber.com",
    "https://www.paytm.com",
    "https://www.phonepe.com",
    "https://www.razorpay.com",
]

# ── 2. KNOWN-PHISHING URLS ─────────────────────────────────────────────────
PHISHING_URLS = [
    "http://paypal-verify.tk/login",
    "http://paypal-secure.ml/account",
    "http://paypa1.com/login",
    "http://secure-paypal.ga/verify",
    "http://192.168.1.1/admin/verify",
    "http://10.0.0.1/login",
    "http://172.16.0.1/admin",
    "http://bit.ly/3xScAmLink",
    "http://tinyurl.com/phishing-url",
    "http://t.co/FakeLink",
    "http://short.link/scam",
    "http://www.google-security-check.tk/verify",
    "http://microsoft-account-verify.ml/login",
    "http://apple-id-verify.cf/password",
    "http://amazon-order-verify.ga/confirm",
    "http://bank-secure-login.xyz/verify",
    "http://verify-account-now.top/login",
    "http://secure-banking.pw/transfer",
    "http://login-verify.click/account",
    "http://account-suspended.tk/reactivate",
    "http://facebook-login-verify.ml/account",
    "http://instagram-verify.ga/login",
    "http://netfl1x.com/login",
    "http://arnazon.com/order",
    "http://micros0ft.com/account",
    "http://g00gle.com/verify",
    "http://paypa1-secure.com/login",
    "http://update-your-account.xyz/bank",
    "http://free-prize-winner.ml/claim",
    "http://lottery-winner-2024.tk/collect",
    "http://urgent-account-verify.ga/login",
    "http://support-microsoft.cf/fix",
    "http://apple-support-urgent.ml/id",
    "http://amazon-package-confirm.tk/verify",
    "http://irs-refund-claim.xyz/form",
    "http://fedex-delivery-confirm.ml/track",
    "http://ups-shipping-verify.ga/package",
    "http://dhl-customs-release.tk/pay",
    "http://netflix-payment-update.cf/billing",
    "http://spotify-account-verify.ml/renew",
    "http://zoom-meeting-secure.tk/join",
    "http://dropbox-shared-file.ml/view",
    "http://onedrive-file-shared.ga/access",
    "http://docusign-document.tk/sign",
    "http://chase-bank-alert.ml/login",
    "http://wellsfargo-secure.ga/verify",
    "http://citibank-alert.tk/account",
    "http://bankofamerica-alert.cf/login",
    "http://coinbase-verify.ml/wallet",
    "http://binance-security.tk/login",
    "http://crypto-airdrop-free.xyz/claim",
    "http://bitcoin-double.ml/send",
    "http://elon-musk-giveaway.tk/btc",
    "http://verify-now-urgent.xyz/account",
    "http://suspended-account.ml/reopen",
    "http://confirm-payment.ga/bank",
    "http://reset-password-now.tk/verify",
    "http://click-here-urgent.cf/win",
    "http://prize-claim-now.ml/winner",
    "http://gift-card-free.ga/redeem",
    "http://login-secure-bank.xyz/transfer",
    "http://pay-now-invoice.tk/urgent",
    "http://final-notice-account.ml/act",
    "http://account-locked-verify.ga/unlock",
    "http://security-alert-google.tk/fix",
    "http://fake-antivirus-renew.ml/pay",
    "http://tech-support-urgent.cf/fix",
    "http://irs-tax-refund.ga/claim",
    "http://social-security-update.tk/verify",
    "http://medicare-benefit.ml/enroll",
    "http://winning-notification.ga/claim",
    "http://inheritance-transfer.tk/accept",
    "http://business-opportunity.ml/invest",
    "http://survey-reward.ga/complete",
    "http://job-offer-legitimate.tk/apply",
    "http://remote-work-opportunity.ml/earn",
]

# ── 3. Also extract URLs from real training data for extra coverage ─────────
print("\n[1] Loading training data for additional URL samples...")
try:
    X_train = pd.read_csv(os.path.join(PROCESSED_DIR, 'X_train.csv'))['text'].fillna('').astype(str)
    y_train = pd.read_csv(os.path.join(PROCESSED_DIR, 'y_train.csv'))['label']

    def extract_urls(text):
        return re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', str(text))

    extra_urls, extra_labels = [], []
    for text, label in zip(X_train, y_train):
        found = extract_urls(text)
        for url in found[:2]:  # cap at 2 per email
            extra_urls.append(url)
            extra_labels.append(label)

    print(f"   Extracted {len(extra_urls)} URLs from training emails")
    # Sample to keep balance
    df_extra = pd.DataFrame({'url': extra_urls, 'label': extra_labels})
    safe_extra   = df_extra[df_extra['label'] == 0].sample(min(500, (df_extra['label']==0).sum()), random_state=42)
    phish_extra  = df_extra[df_extra['label'] == 1].sample(min(500, (df_extra['label']==1).sum()), random_state=42)
    df_extra_bal = pd.concat([safe_extra, phish_extra])
    extra_url_list   = df_extra_bal['url'].tolist()
    extra_label_list = df_extra_bal['label'].tolist()
except Exception as e:
    print(f"   Warning: could not load training data — {e}")
    extra_url_list, extra_label_list = [], []

# ── 4. Build balanced final dataset ──────────────────────────────────────────
all_urls   = SAFE_URLS   + PHISHING_URLS   + extra_url_list
all_labels = [0]*len(SAFE_URLS) + [1]*len(PHISHING_URLS) + extra_label_list

df = pd.DataFrame({'url': all_urls, 'label': all_labels})
print(f"\n[2] Dataset: {len(df)} samples  ({(df.label==0).sum()} safe, {(df.label==1).sum()} phishing)")

X_tr, X_te, y_tr, y_te = train_test_split(df['url'], df['label'], test_size=0.2, random_state=42, stratify=df['label'])

# ── 5. Vectorise ──────────────────────────────────────────────────────────────
print("\n[3] Vectorising...")
url_vectorizer = TfidfVectorizer(
    max_features=3000,
    ngram_range=(1, 3),
    analyzer='char_wb',
    min_df=1
)
X_tr_vec = url_vectorizer.fit_transform(X_tr)
X_te_vec = url_vectorizer.transform(X_te)
print(f"   Vocabulary size: {len(url_vectorizer.vocabulary_)}")
print(f"   IDF fitted: {hasattr(url_vectorizer, 'idf_')}")

# ── 6. Train ──────────────────────────────────────────────────────────────────
print("\n[4] Training RandomForest...")
url_model = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    class_weight='balanced',
    random_state=42,
    n_jobs=-1
)
url_model.fit(X_tr_vec, y_tr)

y_pred = url_model.predict(X_te_vec)
acc = accuracy_score(y_te, y_pred)
print(f"   Accuracy: {acc:.4f}")
print(classification_report(y_te, y_pred, target_names=['safe', 'phishing']))

# ── 7. Save ───────────────────────────────────────────────────────────────────
url_model_path = os.path.join(MODELS_DIR, 'url_model.pkl')
url_vect_path  = os.path.join(MODELS_DIR, 'url_vectorizer.pkl')
joblib.dump(url_model, url_model_path)
joblib.dump(url_vectorizer, url_vect_path)
print(f"\n[5] Saved: {url_model_path}")
print(f"    Saved: {url_vect_path}")

# ── 8. Quick sanity-check predictions ────────────────────────────────────────
print("\n[6] Sanity check predictions:")
test_cases = [
    ("https://www.google.com",            "safe"),
    ("https://www.microsoft.com",         "safe"),
    ("https://www.paypal.com/myaccount",  "safe"),
    ("https://github.com/user/repo",      "safe"),
    ("https://www.amazon.in",             "safe"),
    ("http://paypal-verify.tk/login",     "phishing"),
    ("http://bit.ly/scam",                "phishing"),
    ("http://192.168.1.1/admin",          "phishing"),
    ("http://google-security-check.tk/",  "phishing"),
    ("http://arnazon.com/order",          "phishing"),
]
all_passed = True
for url, expected in test_cases:
    X   = url_vectorizer.transform([url])
    p   = url_model.predict_proba(X)[0]
    pred = "phishing" if p[1] >= 0.5 else "safe"
    ok  = "[OK]" if pred == expected else "[X] "
    if pred != expected:
        all_passed = False
    print(f"   {ok} {pred.upper():8s} ({p[1]:.3f})  {url}")

print("\n" + "=" * 60)
if all_passed:
    print("URL MODEL FIX COMPLETE - All sanity checks passed!")
else:
    print("URL model saved. Some checks failed - review above.")
print("=" * 60)
