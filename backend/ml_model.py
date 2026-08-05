
import os
import sys
import json
import numpy as np

sys.path.insert(0, os.path.dirname(__file__))
from feature_extractor import (
    extract_url_features,
    extract_email_ml_features,
    extract_email_heuristic_features,
    compute_risk_score,
)

try:
    import joblib
    JOBLIB_AVAILABLE = True
except ImportError:
    JOBLIB_AVAILABLE = False

MODEL_DIR = os.path.dirname(__file__)


class PhishingDetector:
    def __init__(self):
        self.url_model   = None
        self.email_model = None
        self.model_meta  = {}
        self._load_models()

    def _load_models(self):
        url_path   = os.path.join(MODEL_DIR, 'url_model.pkl')
        email_path = os.path.join(MODEL_DIR, 'email_model.pkl')
        meta_path  = os.path.join(MODEL_DIR, 'model_meta.json')

        if JOBLIB_AVAILABLE:
            for attr, path, label in [
                ('url_model',   url_path,   'URL'),
                ('email_model', email_path, 'Email'),
            ]:
                if os.path.exists(path):
                    try:
                        setattr(self, attr, joblib.load(path))
                        print(f'[ML] {label} model loaded.')
                    except Exception as e:
                        print(f'[ML] Could not load {label} model: {e}')
                else:
                    print(f'[ML] {label} model not found at {path}. Run train_model.py first.')
        else:
            print('[ML] joblib not available — heuristic mode only.')

        if os.path.exists(meta_path):
            with open(meta_path) as f:
                self.model_meta = json.load(f)

    def analyze_url(self, url: str) -> dict:
        # 30 features for ML + heuristic scoring
        features = extract_url_features(url)
        heuristic = compute_risk_score(features, 'url')

        ml_prob = self._predict(self.url_model, features, 'URL')

        combined_score = self._combine(ml_prob, heuristic['score'])
        mode = 'ML + Heuristic Ensemble' if ml_prob is not None else 'Heuristic Analysis'

        verdict, verdict_label = self._verdict(combined_score)
        return {
            'type':           'url',
            'content':        url,
            'verdict':        verdict,
            'verdictLabel':   verdict_label,
            'confidenceScore': combined_score,
            'mlProbability':  round(ml_prob * 100, 1) if ml_prob is not None else None,
            'analysisMode':   mode,
            'indicators':     self._fmt(heuristic['flags']),
            'summary':        self._summary(verdict, heuristic['flags'], 'url'),
            'featureCount':   len(features),
        }

    def analyze_email(self, email_text: str) -> dict:
        # 8 features for ML model (matches training data)
        ml_features = extract_email_ml_features(email_text)
        # 18 heuristic features for user-facing indicators
        heuristic_features = extract_email_heuristic_features(email_text)
        heuristic = compute_risk_score(heuristic_features, 'email')

        ml_prob = self._predict(self.email_model, ml_features, 'Email')

        combined_score = self._combine(ml_prob, heuristic['score'])
        mode = 'ML + Heuristic Ensemble' if ml_prob is not None else 'Heuristic Analysis'

        verdict, verdict_label = self._verdict(combined_score)
        return {
            'type':           'email',
            'content':        email_text[:500] + ('...' if len(email_text) > 500 else ''),
            'verdict':        verdict,
            'verdictLabel':   verdict_label,
            'confidenceScore': combined_score,
            'mlProbability':  round(ml_prob * 100, 1) if ml_prob is not None else None,
            'analysisMode':   mode,
            'indicators':     self._fmt(heuristic['flags']),
            'summary':        self._summary(verdict, heuristic['flags'], 'email'),
            'featureCount':   len(ml_features),
        }

    def _predict(self, model, features, label=''):
        if model is None:
            return None
        try:
            arr = np.array([features], dtype=float)
            proba = model.predict_proba(arr)[0]
            return float(proba[1])
        except Exception as e:
            print(f'[ML] {label} prediction error: {e}')
            return None

    def _combine(self, ml_prob, heuristic_score):
        if ml_prob is not None:
            score = int(ml_prob * 65 + heuristic_score * 0.35)
        else:
            score = heuristic_score
        return min(score, 100)

    def _verdict(self, score):
        if score >= 65:
            return 'likely_phishing', 'Likely Phishing'
        elif score >= 35:
            return 'suspicious', 'Suspicious'
        else:
            return 'safe', 'Appears Safe'

    def _fmt(self, flags):
        order = {'high': 0, 'medium': 1, 'low': 2}
        return [
            {'name': f[0], 'severity': f[1], 'tip': f[2], 'found': True}
            for f in sorted(flags, key=lambda f: order.get(f[1], 3))
        ]

    def _summary(self, verdict, flags, content_type):
        high   = [f for f in flags if f[1] == 'high']
        medium = [f for f in flags if f[1] == 'medium']
        total  = len(flags)
        if verdict == 'likely_phishing':
            if high:
                return (
                    f'Strong phishing indicators found in this {content_type}. '
                    f'There are {len(high)} high severity and {len(medium)} medium severity alerts. '
                    f'Main issues: {", ".join(f[0] for f in high[:3])}. '
                    'Do not click links, open attachments, or give out personal information.'
                )
            return (
                f'Multiple phishing signals were detected ({total} total flag{"s" if total != 1 else ""}). '
                'This content matches common phishing patterns. '
                'Please treat it as risky and do not interact with it'
            )
        elif verdict == 'suspicious':
            return (
                f'Some suspicious elements were found ({total} flag{"s" if total != 1 else ""}). '
                'Check the source carefully and confirm through official channels before taking action.'
            )
        else:
            if total == 0:
                return (
                    'No phishing indicators were detected. '
                    'The content appears legitimate, but it is still worth staying cautious because no tool is perfect.'
                )
            return (
                f'Mostly safe with {total} minor flag{"s" if total != 1 else ""}. '
                'The overall risk is low, but double-check anything that feels unexpected.'
            )

    def get_status(self):
        return {
            'url_model_loaded':   self.url_model   is not None,
            'email_model_loaded': self.email_model is not None,
            'meta':               self.model_meta,
        }


detector = PhishingDetector()
