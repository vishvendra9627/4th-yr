
import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
)

sys.path.insert(0, os.path.dirname(__file__))
from feature_extractor import extract_url_features, extract_email_ml_features, get_email_ml_feature_names

MODEL_DIR   = os.path.dirname(__file__)
DATASET_DIR = os.path.join(MODEL_DIR, '..', 'Dataset')

URL_SAMPLE_LIMIT     = 15000
EMAIL_PHISHING_LIMIT = 6949
EMAIL_LEGIT_SAMPLE   = 20000

TEST_SIZE   = 0.20
RANDOM_SEED = 42


def print_section(title: str):
    print('\n' + '=' * 60)
    print(f'  {title}')
    print('=' * 60)


def print_metrics(y_true, y_pred, label_names=('Legitimate', 'Phishing')):
    acc  = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec  = recall_score(y_true, y_pred, zero_division=0)
    f1   = f1_score(y_true, y_pred, zero_division=0)

    print(f'  Accuracy  : {acc  * 100:.2f}%')
    print(f'  Precision : {prec * 100:.2f}%')
    print(f'  Recall    : {rec  * 100:.2f}%')
    print(f'  F1-Score  : {f1   * 100:.2f}%')

    print('\n  Classification Report:')
    print(classification_report(y_true, y_pred,
                                target_names=label_names,
                                zero_division=0))

    cm = confusion_matrix(y_true, y_pred)
    print('  Confusion Matrix (rows=Actual, cols=Predicted):')
    print(f'                    Pred Legit   Pred Phishing')
    print(f'  Actual Legit        {cm[0][0]:>6}         {cm[0][1]:>6}')
    print(f'  Actual Phishing     {cm[1][0]:>6}         {cm[1][1]:>6}')
    return acc




def load_url_test_data():
    csv_path = os.path.join(DATASET_DIR, 'phishing_site_urls.csv')
    if not os.path.exists(csv_path):
        print(f'[ERROR] URL dataset not found: {csv_path}')
        return None, None

    df = pd.read_csv(csv_path)
    df = df.dropna(subset=['URL', 'Label'])
    df['y'] = df['Label'].str.lower().map({'bad': 1, 'good': 0})
    df = df.dropna(subset=['y'])
    df['y'] = df['y'].astype(int)

    phishing   = df[df['y'] == 1]
    legitimate = df[df['y'] == 0]

    phishing_sample   = phishing.sample(n=min(URL_SAMPLE_LIMIT, len(phishing)),   random_state=RANDOM_SEED)
    legitimate_sample = legitimate.sample(n=min(URL_SAMPLE_LIMIT, len(legitimate)), random_state=RANDOM_SEED)
    sampled = pd.concat([phishing_sample, legitimate_sample]).sample(frac=1, random_state=RANDOM_SEED)

    print(f'  Loaded {len(sampled)} URL samples — extracting features...')
    X, y = [], []
    for _, row in sampled.iterrows():
        try:
            X.append(extract_url_features(str(row['URL'])))
            y.append(int(row['y']))
        except Exception:
            pass

    return np.array(X, dtype=float), np.array(y)


def test_url_model():
    print_section('URL Model Evaluation')

    model_path = os.path.join(MODEL_DIR, 'url_model.pkl')
    if not os.path.exists(model_path):
        print('  [SKIP] url_model.pkl not found. Run train_model.py first.')
        return None

    X, y = load_url_test_data()
    if X is None:
        return None

    _, X_test, _, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_SEED, stratify=y
    )
    print(f'  Test set: {len(y_test)} samples '
          f'({int(y_test.sum())} phishing, {int((y_test == 0).sum())} legitimate)')

    model  = joblib.load(model_path)
    y_pred = model.predict(X_test)

    return print_metrics(y_test, y_pred)


def load_email_test_data():
    csv_path = os.path.join(DATASET_DIR, 'email_phishing_data.csv')
    if not os.path.exists(csv_path):
        print(f'[ERROR] Email dataset not found: {csv_path}')
        return None, None

    df = pd.read_csv(csv_path)
    expected_cols = get_email_ml_feature_names()
    missing = [c for c in expected_cols if c not in df.columns]
    if missing:
        print(f'[ERROR] Email dataset missing columns: {missing}')
        return None, None

    phishing   = df[df['label'] == 1]
    legitimate = df[df['label'] == 0]

    phishing_sample = phishing.sample(n=min(EMAIL_PHISHING_LIMIT, len(phishing)),   random_state=RANDOM_SEED)
    legit_sample    = legitimate.sample(n=min(EMAIL_LEGIT_SAMPLE,  len(legitimate)), random_state=RANDOM_SEED)
    sampled = pd.concat([phishing_sample, legit_sample]).sample(frac=1, random_state=RANDOM_SEED)

    X = sampled[expected_cols].values
    y = sampled['label'].values
    print(f'  Loaded {len(y)} email samples '
          f'({int(y.sum())} phishing, {int((y == 0).sum())} legitimate)')
    return np.array(X, dtype=float), np.array(y)


def test_email_model():
    print_section('Email Model Evaluation')

    model_path = os.path.join(MODEL_DIR, 'email_model.pkl')
    if not os.path.exists(model_path):
        print('  [SKIP] email_model.pkl not found. Run train_model.py first.')
        return None

    X, y = load_email_test_data()
    if X is None:
        return None

    _, X_test, _, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_SEED, stratify=y
    )
    print(f'  Test set: {len(y_test)} samples '
          f'({int(y_test.sum())} phishing, {int((y_test == 0).sum())} legitimate)')

    model  = joblib.load(model_path)
    y_pred = model.predict(X_test)

    return print_metrics(y_test, y_pred)


def main():
    print_section('Phishing Detector Accuracy Testing')

    meta_path = os.path.join(MODEL_DIR, 'model_meta.json')
    if os.path.exists(meta_path):
        with open(meta_path) as f:
            meta = json.load(f)
        print(f"  Models       : {meta.get('models', 'N/A')}")
        print(f"  URL samples  : {meta.get('url_samples', 'N/A')}")
        print(f"  Email samples: {meta.get('email_samples', 'N/A')}")

    url_acc   = test_url_model()
    email_acc = test_email_model()

    print_section('Summary')
    if url_acc is not None:
        print(f'  URL   Model Accuracy : {url_acc   * 100:.2f}%')
    if email_acc is not None:
        print(f'  Email Model Accuracy : {email_acc * 100:.2f}%')
    if url_acc is not None and email_acc is not None:
        avg = (url_acc + email_acc) / 2
        print(f'  Combined Average     : {avg * 100:.2f}%')
    print()


if __name__ == '__main__':
    main()
