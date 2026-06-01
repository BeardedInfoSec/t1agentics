# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
ML Alert Classifier - Learns from Resolved Alerts

This service trains on historical alert dispositions to predict new alert outcomes.
It provides confidence scores that INFORM Riggs, not replace his reasoning.

Design:
- Input: Alert features (title patterns, source, severity, IOC types, etc.)
- Output: Probability distribution over dispositions + confidence
- Model: XGBoost (fast, interpretable, works with small data)

ML never decides alone. It nudges confidence, nothing more.
Riggs reasons. ML informs.
"""

import json
import logging
import hashlib
import pickle
import os
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    np = None
    HAS_NUMPY = False

logger = logging.getLogger(__name__)

# Model storage path
MODEL_DIR = os.path.join(os.path.dirname(__file__), '..', 'ml_models')
MODEL_PATH = os.path.join(MODEL_DIR, 'alert_classifier.pkl')
VECTORIZER_PATH = os.path.join(MODEL_DIR, 'alert_vectorizer.pkl')
METADATA_PATH = os.path.join(MODEL_DIR, 'model_metadata.json')


@dataclass
class MLPrediction:
    """Prediction result from the ML classifier"""
    disposition: str  # Most likely disposition
    confidence: float  # 0.0 - 1.0
    probabilities: Dict[str, float]  # All disposition probabilities
    features_used: List[str]  # Which features influenced this
    model_version: str
    training_samples: int
    anomaly_score: float = 0.5  # 0.0 = normal, 1.0 = highly anomalous

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses and logging."""
        return {
            'disposition': self.disposition,
            'confidence': self.confidence,
            'probabilities': self.probabilities,
            'features_used': self.features_used,
            'model_version': self.model_version,
            'training_samples': self.training_samples,
            'anomaly_score': self.anomaly_score
        }

    def to_ml_scores(self) -> Dict[str, Any]:
        """Convert to ml_scores format expected by Riggs."""
        return {
            'classification_confidence': self.confidence,
            'predicted_disposition': self.disposition,
            'anomaly_score': self.anomaly_score,
            'probabilities': self.probabilities,
            'model_version': self.model_version
        }


class AlertFeatureExtractor:
    """
    Extract features from alerts for ML classification.

    Feature categories:
    1. Text features (title, description) - TF-IDF
    2. Categorical features (source, severity, alert_type)
    3. IOC features (types present, counts)
    4. Temporal features (hour of day, day of week)
    """

    # Known alert sources for one-hot encoding
    KNOWN_SOURCES = [
        'phishing_report', 'edr', 'siem', 'email_gateway',
        'firewall', 'ids', 'dlp', 'cloud_security', 'manual'
    ]

    # Known severity levels
    SEVERITIES = ['low', 'medium', 'high', 'critical']

    # IOC types to track
    IOC_TYPES = ['ip', 'domain', 'url', 'hash', 'email', 'file_path']

    def extract_features(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract ML features from an alert.

        Returns dict of features suitable for model training/prediction.
        """
        features = {}

        # Parse raw_event if string
        raw_event = alert.get('raw_event', {})
        if isinstance(raw_event, str):
            try:
                raw_event = json.loads(raw_event)
            except:
                raw_event = {}

        # === TEXT FEATURES ===
        title = alert.get('title', '') or ''
        description = alert.get('description', '') or raw_event.get('body', '') or ''

        # Clean and combine text
        text = f"{title} {description}".lower()
        features['text'] = text[:2000]  # Limit length

        # Text length features
        features['title_length'] = len(title)
        features['description_length'] = len(description)
        features['has_description'] = 1 if description else 0

        # === CATEGORICAL FEATURES ===
        source = (alert.get('source', '') or '').lower()
        features['source'] = source

        # One-hot encode source
        for s in self.KNOWN_SOURCES:
            features[f'source_{s}'] = 1 if s in source else 0

        # Severity
        severity = (alert.get('severity', '') or 'medium').lower()
        features['severity'] = severity
        for s in self.SEVERITIES:
            features[f'severity_{s}'] = 1 if severity == s else 0

        # === IOC FEATURES ===
        iocs = raw_event.get('iocs', []) or alert.get('iocs', []) or []
        if isinstance(iocs, str):
            try:
                iocs = json.loads(iocs)
            except:
                iocs = []

        features['ioc_count'] = len(iocs)
        features['has_iocs'] = 1 if iocs else 0

        # Count by IOC type
        for ioc_type in self.IOC_TYPES:
            count = sum(1 for ioc in iocs if ioc.get('type', '').lower() == ioc_type)
            features[f'ioc_{ioc_type}_count'] = count
            features[f'has_ioc_{ioc_type}'] = 1 if count > 0 else 0

        # === KEYWORD FEATURES ===
        # Common indicators in text
        keywords = {
            'phishing': ['phishing', 'credential', 'password', 'login', 'verify', 'urgent'],
            'malware': ['malware', 'virus', 'trojan', 'ransomware', 'payload', 'execute'],
            'suspicious': ['suspicious', 'unusual', 'anomaly', 'unauthorized', 'failed'],
            'legitimate': ['newsletter', 'notification', 'confirmation', 'receipt', 'invoice'],
            'test': ['test', 'training', 'awareness', 'simulation', 'knowbe4', 'proofpoint']
        }

        for category, words in keywords.items():
            features[f'kw_{category}'] = sum(1 for w in words if w in text)

        # === TEMPORAL FEATURES ===
        created_at = alert.get('created_at')
        if created_at:
            if isinstance(created_at, str):
                try:
                    created_at = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                except:
                    created_at = None

            if created_at:
                features['hour_of_day'] = created_at.hour
                features['day_of_week'] = created_at.weekday()
                features['is_weekend'] = 1 if created_at.weekday() >= 5 else 0
                features['is_business_hours'] = 1 if 9 <= created_at.hour <= 17 else 0

        # === ENRICHMENT FEATURES ===
        enrichment = alert.get('enrichment_data', {}) or {}

        # Did any IOC come back malicious?
        has_malicious_ioc = False
        for ioc_data in enrichment.values():
            if isinstance(ioc_data, dict):
                if ioc_data.get('malicious') or ioc_data.get('reputation', '').lower() == 'malicious':
                    has_malicious_ioc = True
                    break
        features['has_malicious_enrichment'] = 1 if has_malicious_ioc else 0

        return features

    def features_to_vector(
        self,
        features: Dict[str, Any],
        vectorizer=None,
        fit: bool = False
    ) -> Tuple[np.ndarray, Any]:
        """
        Convert features dict to numpy array for model.

        If fit=True, creates/updates the vectorizer.
        Returns (feature_vector, vectorizer)
        """
        from sklearn.feature_extraction.text import TfidfVectorizer

        # Separate text and numeric features
        text = features.pop('text', '')

        # Numeric features - predefined order
        numeric_keys = [
            'title_length', 'description_length', 'has_description',
            'ioc_count', 'has_iocs',
            'kw_phishing', 'kw_malware', 'kw_suspicious', 'kw_legitimate', 'kw_test',
            'hour_of_day', 'day_of_week', 'is_weekend', 'is_business_hours',
            'has_malicious_enrichment'
        ]
        # Add source one-hots
        numeric_keys.extend([f'source_{s}' for s in self.KNOWN_SOURCES])
        # Add severity one-hots
        numeric_keys.extend([f'severity_{s}' for s in self.SEVERITIES])
        # Add IOC type features
        for ioc_type in self.IOC_TYPES:
            numeric_keys.extend([f'ioc_{ioc_type}_count', f'has_ioc_{ioc_type}'])

        numeric_vector = np.array([features.get(k, 0) for k in numeric_keys], dtype=np.float32)

        # Text features via TF-IDF
        if vectorizer is None:
            vectorizer = TfidfVectorizer(
                max_features=100,  # Keep it small for speed
                ngram_range=(1, 2),
                stop_words='english'
            )

        if fit:
            text_vector = vectorizer.fit_transform([text]).toarray()[0]
        else:
            text_vector = vectorizer.transform([text]).toarray()[0]

        # Combine
        full_vector = np.concatenate([numeric_vector, text_vector])

        return full_vector, vectorizer


class MLAlertClassifier:
    """
    XGBoost-based alert classifier trained on historical dispositions.

    Usage:
        classifier = MLAlertClassifier()
        await classifier.load_or_train()  # Loads existing or trains new

        prediction = classifier.predict(alert_data)
        # prediction.confidence can inform Riggs's confidence
    """

    # Minimum training samples required
    MIN_TRAINING_SAMPLES = 20

    # Dispositions we classify (maps to what analysts choose)
    DISPOSITIONS = ['benign', 'false_positive', 'suspicious', 'true_positive', 'malicious']

    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.feature_extractor = AlertFeatureExtractor()
        self.metadata = {
            'version': '0.0.0',
            'trained_at': None,
            'training_samples': 0,
            'accuracy': None,
            'disposition_counts': {}
        }
        self._loaded = False

    def is_ready(self) -> bool:
        """Check if model is loaded and ready for predictions."""
        return self._loaded and self.model is not None

    async def load_or_train(self, force_retrain: bool = False) -> Dict[str, Any]:
        """
        Load existing model or train a new one.

        Returns status dict with model info.
        """
        # Ensure model directory exists
        os.makedirs(MODEL_DIR, exist_ok=True)

        # Try loading existing model
        if not force_retrain and os.path.exists(MODEL_PATH):
            try:
                return self._load_model()
            except Exception as e:
                logger.warning(f"Failed to load model, will retrain: {e}")

        # Train new model
        return await self.train()

    def _load_model(self) -> Dict[str, Any]:
        """Load model from disk."""
        with open(MODEL_PATH, 'rb') as f:
            self.model = pickle.load(f)

        with open(VECTORIZER_PATH, 'rb') as f:
            self.vectorizer = pickle.load(f)

        if os.path.exists(METADATA_PATH):
            with open(METADATA_PATH, 'r') as f:
                self.metadata = json.load(f)

        self._loaded = True
        logger.info(f"[ML] Loaded model v{self.metadata.get('version')} trained on {self.metadata.get('training_samples')} samples")

        return {
            'status': 'loaded',
            'version': self.metadata.get('version'),
            'training_samples': self.metadata.get('training_samples'),
            'accuracy': self.metadata.get('accuracy')
        }

    async def train(self, days_back: int = 90) -> Dict[str, Any]:
        """
        Train model on resolved alerts from database.

        Args:
            days_back: How many days of historical data to use

        Returns:
            Training result dict
        """
        from services.postgres_db import postgres_db

        try:
            # Use XGBoost (fast, handles imbalanced data well)
            from xgboost import XGBClassifier
            from sklearn.model_selection import train_test_split
            from sklearn.preprocessing import LabelEncoder
        except ImportError:
            logger.error("[ML] XGBoost not installed. Run: pip install xgboost scikit-learn")
            return {'status': 'error', 'message': 'XGBoost not installed'}

        logger.info(f"[ML] Starting training on alerts from last {days_back} days...")

        # Fetch resolved alerts with dispositions
        async with postgres_db.tenant_acquire() as conn:
            cutoff = datetime.utcnow() - timedelta(days=days_back)

            rows = await conn.fetch("""
                SELECT
                    a.alert_id,
                    a.title,
                    a.description,
                    a.source,
                    a.severity,
                    a.disposition,
                    a.raw_event,
                    a.created_at,
                    i.investigation_data
                FROM alerts a
                LEFT JOIN investigations i ON i.alert_id = a.id
                WHERE a.disposition IS NOT NULL
                  AND a.disposition != ''
                  AND a.created_at >= $1
                ORDER BY a.created_at DESC
                LIMIT 10000
            """, cutoff)

        if len(rows) < self.MIN_TRAINING_SAMPLES:
            logger.warning(f"[ML] Not enough training data: {len(rows)} samples (need {self.MIN_TRAINING_SAMPLES})")
            return {
                'status': 'insufficient_data',
                'samples_found': len(rows),
                'samples_needed': self.MIN_TRAINING_SAMPLES
            }

        logger.info(f"[ML] Found {len(rows)} resolved alerts for training")

        # Extract features and labels
        X_features = []
        y_labels = []
        texts = []
        disposition_counts = {}

        for row in rows:
            alert_dict = {
                'alert_id': row['alert_id'],
                'title': row['title'],
                'description': row['description'],
                'source': row['source'],
                'severity': row['severity'],
                'raw_event': row['raw_event'],
                'created_at': row['created_at']
            }

            # Add investigation enrichment if available
            if row['investigation_data']:
                try:
                    inv_data = json.loads(row['investigation_data']) if isinstance(row['investigation_data'], str) else row['investigation_data']
                    alert_dict['enrichment_data'] = inv_data.get('enrichment', {})
                except:
                    pass

            features = self.feature_extractor.extract_features(alert_dict)
            texts.append(features.get('text', ''))

            # Normalize disposition
            disposition = (row['disposition'] or 'suspicious').lower()
            if disposition not in self.DISPOSITIONS:
                disposition = 'suspicious'  # Default unknown to suspicious

            X_features.append(features)
            y_labels.append(disposition)
            disposition_counts[disposition] = disposition_counts.get(disposition, 0) + 1

        logger.info(f"[ML] Disposition distribution: {disposition_counts}")

        # Convert to vectors - fit vectorizer on all texts first
        from sklearn.feature_extraction.text import TfidfVectorizer
        self.vectorizer = TfidfVectorizer(max_features=100, ngram_range=(1, 2), stop_words='english')
        self.vectorizer.fit(texts)

        # Now convert all features to vectors
        X = []
        for i, features in enumerate(X_features):
            features['text'] = texts[i]
            vec, _ = self.feature_extractor.features_to_vector(features, self.vectorizer, fit=False)
            X.append(vec)

        X = np.array(X)

        # Encode labels
        label_encoder = LabelEncoder()
        label_encoder.classes_ = np.array(self.DISPOSITIONS)
        y = label_encoder.transform(y_labels)

        # Split train/test
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        # Train XGBoost
        self.model = XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            objective='multi:softprob',
            num_class=len(self.DISPOSITIONS),
            use_label_encoder=False,
            eval_metric='mlogloss',
            random_state=42
        )

        self.model.fit(X_train, y_train)

        # Evaluate
        accuracy = self.model.score(X_test, y_test)
        logger.info(f"[ML] Model accuracy: {accuracy:.2%}")

        # Update metadata
        self.metadata = {
            'version': datetime.utcnow().strftime('%Y%m%d.%H%M%S'),
            'trained_at': datetime.utcnow().isoformat(),
            'training_samples': len(rows),
            'accuracy': round(accuracy, 4),
            'disposition_counts': disposition_counts,
            'feature_count': X.shape[1]
        }

        # Save model
        self._save_model()
        self._loaded = True

        logger.info(f"[ML] Training complete. Model v{self.metadata['version']} saved.")

        return {
            'status': 'trained',
            'version': self.metadata['version'],
            'training_samples': self.metadata['training_samples'],
            'accuracy': self.metadata['accuracy'],
            'disposition_counts': disposition_counts
        }

    def _save_model(self):
        """Save model to disk."""
        os.makedirs(MODEL_DIR, exist_ok=True)

        with open(MODEL_PATH, 'wb') as f:
            pickle.dump(self.model, f)

        with open(VECTORIZER_PATH, 'wb') as f:
            pickle.dump(self.vectorizer, f)

        with open(METADATA_PATH, 'w') as f:
            json.dump(self.metadata, f, indent=2)

        logger.info(f"[ML] Model saved to {MODEL_DIR}")

    def predict(self, alert: Dict[str, Any]) -> Optional[MLPrediction]:
        """
        Predict disposition for an alert.

        Args:
            alert: Alert data dict

        Returns:
            MLPrediction with confidence scores, or None if model not ready
        """
        if not self.is_ready():
            return None

        try:
            # Extract features
            features = self.feature_extractor.extract_features(alert)
            text = features.get('text', '')
            features['text'] = text

            # Convert to vector
            vec, _ = self.feature_extractor.features_to_vector(features, self.vectorizer, fit=False)
            X = vec.reshape(1, -1)

            # Get probabilities
            probas = self.model.predict_proba(X)[0]

            # Build result
            prob_dict = {disp: float(prob) for disp, prob in zip(self.DISPOSITIONS, probas)}
            best_idx = np.argmax(probas)
            best_disposition = self.DISPOSITIONS[best_idx]
            confidence = float(probas[best_idx])

            # Identify important features
            features_used = []
            if features.get('has_malicious_enrichment'):
                features_used.append('malicious_enrichment')
            if features.get('kw_phishing', 0) > 0:
                features_used.append('phishing_keywords')
            if features.get('kw_test', 0) > 0:
                features_used.append('test_indicators')
            if features.get('has_iocs'):
                features_used.append('has_iocs')

            # Calculate anomaly score based on prediction entropy and feature signals
            anomaly_score = self._calculate_anomaly_score(probas, features, alert)

            return MLPrediction(
                disposition=best_disposition,
                confidence=confidence,
                probabilities=prob_dict,
                features_used=features_used,
                model_version=self.metadata.get('version', 'unknown'),
                training_samples=self.metadata.get('training_samples', 0),
                anomaly_score=anomaly_score
            )

        except Exception as e:
            logger.error(f"[ML] Prediction failed: {e}")
            return None

    def _calculate_anomaly_score(
        self,
        probabilities: np.ndarray,
        features: Dict[str, Any],
        alert: Dict[str, Any]
    ) -> float:
        """
        Calculate an anomaly score based on prediction uncertainty and feature signals.

        Anomaly score ranges from 0.0 (normal/expected) to 1.0 (highly anomalous).

        Factors that increase anomaly:
        - High prediction entropy (uncertain model)
        - Presence of malicious indicators
        - Unusual temporal patterns
        - High keyword density for suspicious terms
        - Mismatch between severity and disposition

        Returns:
            Float between 0.0 and 1.0
        """
        anomaly_factors = []

        # Factor 1: Prediction entropy (uncertainty)
        # Low max probability = more uncertain = more anomalous
        max_prob = float(np.max(probabilities))
        entropy_anomaly = 1.0 - max_prob  # Higher when model is uncertain
        anomaly_factors.append(('entropy', entropy_anomaly, 0.3))

        # Factor 2: Malicious enrichment signals
        if features.get('has_malicious_enrichment'):
            anomaly_factors.append(('malicious_enrichment', 0.8, 0.25))

        # Factor 3: Suspicious keyword density
        kw_suspicious = features.get('kw_suspicious', 0)
        kw_malware = features.get('kw_malware', 0)
        kw_phishing = features.get('kw_phishing', 0)
        threat_keywords = kw_suspicious + kw_malware + kw_phishing
        if threat_keywords > 0:
            keyword_anomaly = min(threat_keywords / 5.0, 1.0)  # Cap at 5 keywords
            anomaly_factors.append(('threat_keywords', keyword_anomaly, 0.2))

        # Factor 4: Unusual time (outside business hours + weekend)
        is_weekend = features.get('is_weekend', 0)
        is_business_hours = features.get('is_business_hours', 1)
        if is_weekend or not is_business_hours:
            anomaly_factors.append(('unusual_time', 0.4, 0.1))

        # Factor 5: High MALICIOUS IOC count (NOT total IOC count - many IOCs is normal in legitimate emails)
        # Only flag if there are actual malicious IOCs found
        malicious_ioc_count = features.get('malicious_ioc_count', 0)
        if malicious_ioc_count > 0:
            ioc_anomaly = min(malicious_ioc_count / 3.0, 1.0)  # Even 1 malicious IOC is significant
            anomaly_factors.append(('malicious_iocs', ioc_anomaly, 0.25))

        # Factor 6: Severity mismatch (high severity but ML thinks benign)
        severity = (alert.get('severity') or '').lower()
        predicted_idx = int(np.argmax(probabilities))
        predicted_disp = self.DISPOSITIONS[predicted_idx]

        if severity in ('critical', 'high') and predicted_disp in ('benign', 'false_positive'):
            anomaly_factors.append(('severity_mismatch', 0.7, 0.15))
        elif severity in ('low', 'medium') and predicted_disp in ('malicious', 'true_positive'):
            anomaly_factors.append(('severity_mismatch', 0.5, 0.1))

        # Calculate weighted anomaly score
        if not anomaly_factors:
            return 0.3  # Default baseline anomaly

        total_weight = sum(weight for _, _, weight in anomaly_factors)
        weighted_sum = sum(score * weight for _, score, weight in anomaly_factors)

        # Normalize and clamp
        anomaly_score = weighted_sum / total_weight if total_weight > 0 else 0.3
        anomaly_score = max(0.0, min(1.0, anomaly_score))

        logger.debug(
            f"[ML_ANOMALY] score={anomaly_score:.2f} factors={[(n, f'{s:.2f}') for n, s, _ in anomaly_factors]}"
        )

        return round(anomaly_score, 3)

    def get_model_info(self) -> Dict[str, Any]:
        """Get current model metadata."""
        return {
            'ready': self.is_ready(),
            **self.metadata
        }


# Global singleton
_classifier_instance = None


def get_ml_classifier() -> MLAlertClassifier:
    """Get the global ML classifier instance."""
    global _classifier_instance
    if _classifier_instance is None:
        _classifier_instance = MLAlertClassifier()
    return _classifier_instance


async def initialize_ml_classifier(force_retrain: bool = False) -> Dict[str, Any]:
    """Initialize the ML classifier (load or train)."""
    classifier = get_ml_classifier()
    return await classifier.load_or_train(force_retrain)
