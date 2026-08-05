from ntpath import join
import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.pipeline import Pipeline
from sklearn.utils import resample

sys.path.insert(0, os.path.dirname(__file__))
from feature_extractor import (
    extract_url_features, extract_email_ml_features,
    get_email_ml_feature_names )

DATASET_DIR = os.path.join(os.path.dirname(__file__),'..', 'Dataset')
MODEL_DIR   = os.path.dirname(__file__)


URL_SAMPLE_LIMIT   = 15000 
EMAIL_PHISHING_LIMIT = 6949 
EMAIL_LEGIT_SAMPLE = 20000

def load_csv_url_data():
    """ load phishing_site_urls.csv -> extract URL features -> return X, y """
    csv_path = os.path.join(DATASET_DIR, 'phishing_site_urls.csv')
    if not os.path.exists(csv_path):
        print(f'[ERROR] URL dataset not found at {csv_path}')
        return None, None
    
    print(f'[DATA] Loading URL dataset from {csv_path}...')
    df = pd.read_csv(csv_path)

   
    df = df.dropna(subset=['URL', 'Label'])
    df['y'] = df['Label'].str.lower().map({'bad': 1, 'good': 0})
    
    df = df.dropna(subset=['y'])
    df['y']= df['y'].astype(int)

    phihsing = df[df['y'] == 1]
    legitimate = df[df['y'] == 0]

    phihsing_sample = phihsing.sample(n=min(URL_SAMPLE_LIMIT, len(phihsing)), random_state=42)
    legitimate_sample = legitimate.sample(n=min(URL_SAMPLE_LIMIT, len(legitimate)), random_state=42)
  
    sampled = pd.concat([phihsing_sample, legitimate_sample]).sample(frac=1, random_state=42)

    print(f'[DATA] Extracting features from {len(sampled)} URLs...')
    X, y = [], []
    errors = 0
    for _, row in sampled.iterrows():
        url = row['URL']
        label = row['y']
        try:
            X.append(extract_url_features(str(row['URL'])))
            y.append(int(row['y']))
        except Exception:
            errors += 1
    print(f'[DATA] URL samples loaded ({sum(y)} phishing, {len(y)-sum(y)} legitimate), {errors} errors.')
    return X, y

def load_csv_email_data(): 
    """
    load email_phishing_data.csv.
    The CSV already has pre-extracted features for ML, so we just need to load them and split into X, y.
    no re-sampling needed since the dataset is already balanced (6949 phishing, 6949 legitimate).
    """
    csv_path= os.path.join(DATASET_DIR, 'email_phishing_data.csv')
    if not os.path.exists(csv_path):
        print(f'[ERROR] Email dataset not found at {csv_path}')
        return None, None
    print(f'[DATA] Loading email dataset from {csv_path}...')
    df = pd.read_csv(csv_path)

    expected_cols = get_email_ml_feature_names()
    missing = [c for c in expected_cols if c not in df.columns]
    if missing:
        print(f'[ERROR] Email dataset is missing expected columns: {missing}')
        return None, None
    phishing = df[df['label'] == 1]
    legitimate = df[df['label'] == 0]

    phishing_sample = phishing.sample(n=min(EMAIL_PHISHING_LIMIT, len(phishing)), random_state=42)
    legit_sample    = legitimate.sample(n=min(EMAIL_LEGIT_SAMPLE, len(legitimate)),         random_state=42)
    sampled         = pd.concat([phishing_sample, legit_sample]).sample(frac=1, random_state=42)

    X = sampled[expected_cols].values.tolist()
    y = sampled['label'].values.tolist()

    print(f' -> {len(X)} email samples loaded ({sum(y)} phishing, {len(y)-sum(y)} legitimate)')
    return X, y

def generate_synthetic_url_data():
    """Fallback: self-made phishing and legitimate URLs with extracted features. This is very basic and should be replaced with real data."""

    phishing_urls = [
        'http://malicious.com/login',
        'https://secure-bank.com/account',
        'http://phishing-site.net/verify',
        'https://fake-paypal.com/update',
        'http://dangerous.org/confirm',
        'http://paypa1.com/login/secure', 'http://192.168.1.1/amazon/login.php',
        'https://paypal-secure-update.xyz/verify', 'http://bit.ly/3xPhishingLink',
        'http://secure.paypal.com.evil.xyz/login', 'http://amazon-account-verify.tk/update',
        'http://google.com@evil.com/phish', 'http://login-apple-id-verify-account.com/secure',
        'http://192.0.2.1/bank/login.html?redirect=http://evil.com',
        'http://bankofamerica-secure.ml/account/verify.php',
        'http://tinyurl.com/abc123phish', 'http://paypal-login.ga/auth/secure',
        'http://microsoft-verify.work/account', 'http://facebook-login-secure.cf/auth',
        'http://netflix-update.pw/billing/payment.html'
        'http://secure-login-uwl.com/verify', 'http://github.com.evil.com/login',
        'http://linkedin-secure-update.com/account/verify',
        'http://twitter-login-secure.net/auth', 'http://instagram-update.xyz/verify',   
        'http://reddit-login-secure.com/auth', 'http://wikipedia-update.net/verify',
        'http://bing-login-secure.com/auth', 'http://dropbox-update.net/verify',
        'http://spotify-login-secure.com/auth', 'http://adobe-update.net/verify',
        'http://slack-login-secure.com/auth', 'http://twitch-update.net/verify',
        'http://airbnb-login-secure.com/auth', 'http://github-update.net/verify',
        'http://stackoverflow-login-secure.com/auth', 'http://uwl-update.net/verify',


    
    ]
    legitimate_urls = [
        'https://www.google.com',
        'https://www.facebook.com',
        'https://www.amazon.com',
        'https://www.apple.com',
        'https://www.microsoft.com',
        'https://www.netflix.com',
        'https://www.paypal.com',
        'https://www.linkedin.com',
        'https://www.twitter.com',
        'https://www.instagram.com',
        'https://www.reddit.com',
        'https://www.wikipedia.org',
        'https://www.yahoo.com',
        'https://www.bing.com',
        'https://www.dropbox.com',
        'https://www.spotify.com',
        'https://www.adobe.com',
        'https://www.slack.com',
        'https://www.twitch.tv',
        'https://www.airbnb.com',
        'https://www.github.com',
        'https://www.stackoverflow.com',
        'https://www.uwl.ac.uk',
        'https://www.uwlsu.com',
        'https://www.uwl.ac.uk/course/undergraduate/cyber-security?start=1730&option=33',
        'https://www.kaggle.com/',
        'https://www.coursera.org/learn/machine-learning'
        'https://www.edx.org/course/introduction-to-computer-science-and-programming-using-python', 
        'https://www.udemy.com/course/machinelearning/',
        'https://www.datacamp.com/courses/intro-to-python-for-data-science',
        'https://www.codecademy.com/learn/learn-python-3',
        'https://www.freecodecamp.org/learn/scientific-computing-with-python/',
        'https://www.khanacademy.org/computing/computer-programming/python',
    ]

    X, y = [], []
    for url in phishing_urls:
        try:
            X.append(extract_url_features(url))
            y.append(1)
        except Exception:
            pass
    for url in legitimate_urls:
        try:
            X.append(extract_url_features(url))
            y.append(0)
        except Exception:
            pass
    return X, y


def generate_synthetic_email_data():
    """Fallback:  self-made phishing and legitimate email texts with extracted features. This is very basic and should be replaced with real data."""
    phishing_emails = [
    "Dear Customer, Your account will be suspended within 24 hours. Please verify your password and credit card information immediately by clicking here: http://bit.ly/verify123",
    "Congratulations! You've won a $1000 gift card. To claim your prize, please provide your personal details and credit card information at http://fakeprize.com/claim",
    "Urgent: Unusual activity detected on your bank account. Please log in to http://secure-bank.com/login to review your transactions and secure your account.",
    "Your package delivery has failed. Please click the link to reschedule: http://phishing-delivery.com/reschedule",
    "We noticed a login attempt from an unrecognized device. If this was not you, please verify your account immediately at http://account-security.com/verify",
    "Your email account has been compromised. Please reset your password immediately at http://email-security.com/reset",
    "Dear User, Your subscription is expiring soon. Please update your payment information at http://subscription-update.com/payment",
    "Your tax refund is ready! Please provide your social security number and bank details at http://tax-refund.com/claim",
    "Important: Your account has been flagged for suspicious activity. Please verify your identity at http://account-verify.com/secure",
    "You have received a secure message. Please log in to http://secure-message.com/login to view it.",
    "Dear Valued Customer, We are updating our privacy policy. Please review and accept the new terms at http://privacy-update.com/accept",
    "Your account has been temporarily locked due to multiple failed login attempts. Please verify your identity at http://account-lock.com/verify",
    "Congratulations! You've been selected for a free vacation. To claim your prize, please provide your personal details and credit card information at http://free-vacation.com/claim",
    "Urgent: Your account will be deleted within 48 hours. Please verify your information immediately at http://account-deletion.com/verify",
    "Your email account has been compromised. Please reset your password immediately at http://email-security.com/reset",
    "Dear User, Your subscription is expiring soon. Please update your payment information at http://subscription-update.com/payment",
    "Your tax refund is ready! Please provide your social security number and bank details at http://tax-refund.com/claim",
    "Important: Your account has been flagged for suspicious activity. Please verify your identity at http://account-verify.com/secure",
    "You have received a secure message. Please log in to http://secure-message.com/login to view it.", 
    "Dear Valued Customer, We are updating our privacy policy. Please review and accept the new terms at http://privacy-update.com/accept", 
    "Your account has been temporarily locked due to multiple failed login attempts. Please verify your identity at http://account-lock.com/verify" 

    ]

    legitimate_emails = [
        "Hi John, Just wanted to check in and see how you're doing. Let's catch up soon! Best, Jane",
        "Dear Team, Please find attached the report for this quarter's sales performance. Let me know if you have any questions. Regards, Sarah",
        "Hello Mike, It was great meeting you at the conference last week. Let's stay in touch! Cheers, Tom",
        "Dear Customer, Thank you for your recent purchase. Your order will be shipped within 3-5 business days. Best regards, Online Store",
        "Hi Emily, I hope you're having a wonderful day! Just wanted to share some exciting news with you. Talk soon! Best, David",
        "Dear Colleagues, Please be reminded of the upcoming team meeting scheduled for next Monday at 10 AM. Looking forward to seeing everyone there! Regards, Manager",
        "Hello Anna, I wanted to thank you for your help on the project last week. Your insights were invaluable! Best wishes, Mark",
        "Dear Valued Customer, We are pleased to inform you that your subscription has been successfully renewed. Thank you for your continued support! Best regards, Service Team",
        "Hi Chris, Just a quick note to say congratulations on your recent promotion! Well deserved! Cheers, Alex",
        "Dear Team, Please find attached the agenda for tomorrow's meeting. Let me know if you have any additional topics to discuss. Regards, Supervisor"
        "Good morning Eman, i hope this email finds you well. I wanted to follow up on our previous conversation regarding the project timeline. Please let me know if you have any updates or if there's anything I can assist with on task 3. Best regards, Devin",
        "Dear Customer, We are excited to announce the launch of our new product line. Visit our website to learn more and take advantage of exclusive offers! Best regards, Marketing Team",
        "Hi Lisa, I hope you're doing well! I wanted to share some exciting news with you about an upcoming event. Let's catch up soon! Best, Kevin",
        "Dear Colleagues, Please be reminded of the upcoming team meeting scheduled for next Wednesday at 2 PM. Looking forward to seeing everyone there! Regards, Team Lead",
        "Hello Carlos I wanted to thank you for your Help on the project last week. kind regards, Devin",

    ]
    X, y = [], []
    for email in phishing_emails:
        try:
            X.append(extract_email_ml_features(email))
            y.append(1)
        except Exception:
            pass
    for email in legitimate_emails:
        try:
            X.append(extract_email_ml_features(email))
            y.append(0)
        except Exception:
            pass
    return X, y

def build_ensemble_model():
    rf = RandomForestClassifier(n_estimators=200, max_depth=15, min_samples_split=4, min_samples_leaf=2, random_state=42, class_weight='balanced')

    gb = GradientBoostingClassifier(n_estimators=150, learning_rate=0.1, max_depth=5, random_state=42)
    lr = LogisticRegression(max_iter=1000, random_state=42, class_weight='balanced')
    ensemble = VotingClassifier(estimators=[('rf', rf), ('gb', gb), ('lr', lr)], voting='soft', weights=[3, 2, 1])
    return Pipeline([('scaler', StandardScaler()), ('classifier', ensemble)])
def train_and_save():
    print('='* 60)
    print('[TRAIN] Starting training process...')
    print('='* 60)


    # Load and prepare URL data

    print('\n[1/4] Loading and preparing URL data...')
    X_url, y_url = load_csv_url_data()
    syn_X, syn_y = generate_synthetic_url_data()
    if not X_url:
        print('[WARN] Real URL data not available, using synthetic data only.')
        X_url, y_url = syn_X, syn_y
    else:
        X_url+= syn_X   
        y_url+= syn_y
    print(f' Total URL samples for training:{len(X_url)}')

    print('\n[2/4] Training URL model (Random Forest + Gradient Boosting + Logistic Regression)...')
    url_arr = np.array(X_url, dtype=float)
    url_y_arr = np.array(y_url)
    url_model = build_ensemble_model()

    cv_folds =min(5, len(url_arr) // max(int(url_y_arr.sum()), 1))
    cv_folds = max(cv_folds, 2)
    cv_scores = cross_val_score(build_ensemble_model(), url_arr, url_y_arr, cv=cv_folds, scoring='accuracy')
    print(f' URL Model CV Accuracy: {cv_scores.mean():.3f} (+/- {cv_scores.std():.3f})')

    url_model.fit(url_arr, url_y_arr)
    url_path = os.path.join(MODEL_DIR, 'url_model.pkl')
    joblib.dump(url_model, url_path)
    print(f' URL model saved to {url_path}')

    # Load and prepare email data
    print('\n[3/4] Loading and preparing email data...')
    X_email, y_email = load_csv_email_data()
    syn_X_email, syn_y_email = generate_synthetic_email_data()
    if not X_email:
        print('  No CSV data found — using synthetic data only.')
        X_email, y_email = syn_X_email, syn_y_email
    else:
        X_email += syn_X_email
        y_email += syn_y_email
    print(f'  Total email samples: {len(X_email)}')

    print('\n[4/4] Training email model...')
    email_arr = np.array(X_email, dtype=float)
    email_y_arr = np.array(y_email)
    email_model = build_ensemble_model()

    cv_folds = min(5, len(email_arr) // max(int(email_y_arr.sum()), 1))
    cv_folds = max(cv_folds, 2)
    cv_scores = cross_val_score(build_ensemble_model(), email_arr, email_y_arr, cv=cv_folds, scoring='f1')
    print(f'  Cross-val F1: {cv_scores.mean():.3f} (+/- {cv_scores.std():.3f})')

    email_model.fit(email_arr, email_y_arr)
    email_path = os.path.join(MODEL_DIR, 'email_model.pkl')
    joblib.dump(email_model, email_path)
    print(f'  Email model saved -> {email_path}')

    # Save model metadata
    meta = {
        'url_samples': len(X_url),
        'email_samples': len(X_email),
        'url_features': 30,
        'email_features': 8,
        'email_feature_names': get_email_ml_feature_names(),
        'models': 'RandomForest + GradientBoosting + LogisticRegression (VotingEnsemble)',
        'datasets': ['phishing_site_urls.csv', 'email_phishing_data.csv'],
    }
    with open(os.path.join(MODEL_DIR, 'model_meta.json'), 'w') as f:
        json.dump(meta, f, indent=2)

    print('\n' + '=' * 60)
    print('  Training complete! Both models ready.')
    print('=' * 60)


if __name__ == '__main__':
    train_and_save() 