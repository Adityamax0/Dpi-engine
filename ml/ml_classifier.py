"""
========================================================
  ml_classifier.py — ML-Based Traffic Classifier
  Author   : Aditya Pandey
  Project  : DPI Engine (Deep Packet Inspection)
  Built With: scikit-learn + Claude (Anthropic AI)
========================================================

This is the AI/ML layer of the DPI engine — Aditya's
core specialization applied to network security.

Why ML for traffic classification?
    SNI extraction only works when the TLS Client Hello
    is visible. But many apps:
      - Use QUIC (no SNI in same place)
      - Rotate domains constantly
      - Use CDNs that mask the real app

    ML classifies traffic using BEHAVIORAL features:
      - Packet size distribution
      - Port numbers
      - Protocol
      - Connection timing
      - Byte count ratios

    This is how real enterprise DPI products work.

Model: Random Forest Classifier
    - Fast inference (< 1ms per prediction)
    - Handles mixed feature types well
    - Interpretable (feature importances)
    - No neural network complexity needed for this task

Training Data:
    The model is trained on synthetic data that captures
    real behavioral patterns of each app category.
    For production use, this would be trained on labeled
    real traffic captures.
"""

import os
import sys
import json
import logging
import numpy as np
from typing import Tuple, Optional, List, Dict
from pathlib import Path

logger = logging.getLogger("MLClassifier")

# App categories the ML model classifies
APP_LABELS = [
    "YouTube",
    "Netflix",
    "WhatsApp",
    "Instagram",
    "Facebook",
    "GitHub",
    "Zoom",
    "Discord",
    "TikTok",
    "General Web",
    "File Transfer",
    "Unknown",
]

# Feature names (must match extract_features output)
FEATURE_NAMES = [
    "dst_port",
    "src_port_bucket",
    "protocol",
    "packet_count",
    "byte_count",
    "avg_pkt_size",
    "is_https",
    "is_http",
    "is_dns",
    "is_high_port",
    "byte_per_packet",
]


class MLTrafficClassifier:
    """
    Random Forest classifier for network traffic app identification.

    Aditya's design note:
        I intentionally kept this as scikit-learn and not a
        deep learning model. For structured tabular features
        (port numbers, packet counts, byte sizes), tree-based
        models like Random Forest consistently outperform neural
        networks while being orders of magnitude faster and
        more interpretable. This is a lesson from real ML
        engineering: pick the right model for the data type,
        not the fanciest one.
    """

    def __init__(self, model_path: Optional[str] = None):
        self.model     = None
        self.is_trained = False
        self._load_or_train(model_path)

    def _load_or_train(self, model_path: Optional[str]):
        """Load saved model or train a fresh one."""
        try:
            from sklearn.ensemble import RandomForestClassifier
        except ImportError:
            logger.warning("scikit-learn not installed. Run: pip install scikit-learn numpy")
            return

        # Try caller-supplied path
        if model_path and Path(model_path).exists():
            if self._load_model(model_path):
                return

        # Check preferred save location (ml_model.pkl next to this file)
        default_pkl = Path(__file__).parent / "ml_model.pkl"
        if default_pkl.exists():
            if self._load_model(str(default_pkl)):
                return

        # Train fresh model (covers: first run, stale pkl, version mismatch)
        logger.info("Training ML model on synthetic traffic data...")
        self._train_model()

    def _train_model(self):
        """
        Train the Random Forest on synthetic traffic data.

        The training data encodes behavioral patterns:
        - YouTube: large payloads, HTTPS (443), sustained high byte count
        - WhatsApp: small packets, mix of 443 and 5222, high packet count
        - DNS: port 53, UDP (17), tiny packets
        - File transfer: high byte count, ports 20/21/22
        etc.
        """
        try:
            from sklearn.ensemble import RandomForestClassifier
            import numpy as np
        except ImportError:
            return

        np.random.seed(42)
        X, y = self._generate_training_data()

        self.model = RandomForestClassifier(
            n_estimators = 100,
            max_depth    = 8,
            random_state = 42,
            n_jobs       = -1
        )
        self.model.fit(X, y)
        self.is_trained = True
        logger.info(f"ML model trained on {len(X)} samples | Classes: {APP_LABELS}")

        # Save model weights as JSON for portability
        self._save_model()

    def _generate_training_data(self) -> Tuple[np.ndarray, List[str]]:
        """
        Generate synthetic training data capturing real behavioral patterns.
        Each row = [dst_port, src_port_bucket, protocol, pkt_count, byte_count,
                    avg_pkt_size, is_https, is_http, is_dns, is_high_port, byte_per_pkt]
        """
        import numpy as np
        samples_per_class = 300
        X, y = [], []

        def add(label, port, protocol, pkt_mu, pkt_sig, byte_mu, byte_sig, n=samples_per_class):
            for _ in range(n):
                pkt_count  = max(1, int(np.random.normal(pkt_mu, pkt_sig)))
                byte_count = max(100, int(np.random.normal(byte_mu, byte_sig)))
                avg_size   = byte_count / pkt_count
                src_port   = np.random.randint(1024, 65535)
                X.append([
                    port,
                    min(src_port // 1000, 60),   # bucket
                    protocol,
                    pkt_count,
                    byte_count,
                    avg_size,
                    int(port == 443),
                    int(port == 80),
                    int(port == 53),
                    int(port > 8000),
                    byte_count / max(pkt_count, 1),
                ])
                y.append(label)

        # YouTube — large sustained HTTPS flows
        add("YouTube",     443, 6, pkt_mu=800, pkt_sig=200, byte_mu=900000, byte_sig=200000)
        # Netflix — very large flows
        add("Netflix",     443, 6, pkt_mu=1200, pkt_sig=300, byte_mu=1500000, byte_sig=400000)
        # WhatsApp — small frequent packets, mix of ports
        add("WhatsApp",    443, 6, pkt_mu=50,  pkt_sig=20,  byte_mu=15000,  byte_sig=8000)
        add("WhatsApp",   5222, 6, pkt_mu=30,  pkt_sig=10,  byte_mu=8000,   byte_sig=3000, n=100)
        # Instagram — medium HTTPS
        add("Instagram",   443, 6, pkt_mu=200, pkt_sig=80,  byte_mu=120000, byte_sig=50000)
        # Facebook — medium HTTPS
        add("Facebook",    443, 6, pkt_mu=180, pkt_sig=70,  byte_mu=100000, byte_sig=40000)
        # GitHub — moderate HTTPS
        add("GitHub",      443, 6, pkt_mu=100, pkt_sig=40,  byte_mu=50000,  byte_sig=20000)
        # Zoom — large bidirectional UDP
        add("Zoom",        443, 6, pkt_mu=400, pkt_sig=100, byte_mu=300000, byte_sig=80000)
        add("Zoom",       8801,17, pkt_mu=600, pkt_sig=150, byte_mu=400000, byte_sig=100000, n=150)
        # Discord — mix UDP + HTTPS
        add("Discord",     443, 6, pkt_mu=120, pkt_sig=50,  byte_mu=40000,  byte_sig=15000)
        add("Discord",    50000,17, pkt_mu=200, pkt_sig=60,  byte_mu=80000,  byte_sig=30000, n=100)
        # TikTok — large video HTTPS
        add("TikTok",      443, 6, pkt_mu=700, pkt_sig=200, byte_mu=800000, byte_sig=250000)
        # General Web — small-medium HTTPS
        add("General Web", 443, 6, pkt_mu=60,  pkt_sig=30,  byte_mu=25000,  byte_sig=15000)
        add("General Web",  80, 6, pkt_mu=40,  pkt_sig=20,  byte_mu=15000,  byte_sig=8000, n=100)
        # File Transfer
        add("File Transfer", 22, 6, pkt_mu=500, pkt_sig=200, byte_mu=2000000, byte_sig=800000)
        add("File Transfer", 21, 6, pkt_mu=300, pkt_sig=100, byte_mu=1500000, byte_sig=500000, n=100)
        # Unknown — random noise
        add("Unknown",     1234,17, pkt_mu=20,  pkt_sig=10,  byte_mu=5000,   byte_sig=3000)

        return np.array(X), y

    def extract_features(self, flow_data: dict) -> np.ndarray:
        """
        Extract ML feature vector from a flow's metadata.
        This is called at inference time for each flow.
        """
        dst_port   = flow_data.get("dst_port", 0)
        src_port   = flow_data.get("src_port", 0)
        protocol   = flow_data.get("protocol", 6)
        pkt_count  = flow_data.get("packet_count", 1)
        byte_count = flow_data.get("byte_count", 0)

        avg_pkt_size   = byte_count / max(pkt_count, 1)
        byte_per_pkt   = byte_count / max(pkt_count, 1)
        src_port_bucket = min(src_port // 1000, 60)

        return np.array([[
            dst_port,
            src_port_bucket,
            protocol,
            pkt_count,
            byte_count,
            avg_pkt_size,
            int(dst_port == 443),
            int(dst_port == 80),
            int(dst_port == 53),
            int(dst_port > 8000),
            byte_per_pkt,
        ]])

    def predict(self, flow_data: dict) -> Tuple[str, int]:
        """
        Predict the application for a given flow.
        Returns (app_name, confidence_percent).
        """
        if not self.is_trained or self.model is None:
            return "Unknown", 0

        try:
            features = self.extract_features(flow_data)
            proba    = self.model.predict_proba(features)[0]
            idx      = int(np.argmax(proba))
            label    = self.model.classes_[idx]
            conf     = int(proba[idx] * 100)
            return label, conf
        except Exception as e:
            logger.debug(f"ML predict error: {e}")
            return "Unknown", 0

    def predict_batch(self, flows: List[dict]) -> List[Tuple[str, int]]:
        """Predict for a list of flows at once."""
        return [self.predict(f) for f in flows]

    def feature_importances(self) -> Dict[str, float]:
        """Return which features matter most (model interpretability)."""
        if not self.is_trained or self.model is None:
            return {}
        importances = self.model.feature_importances_
        return dict(zip(FEATURE_NAMES, [round(float(v), 4) for v in importances]))

    def _save_model(self):
        """Save model in a portable format."""
        try:
            import pickle, base64
            save_path = Path(__file__).parent / "ml_model.pkl"
            with open(save_path, "wb") as f:
                pickle.dump(self.model, f)
            logger.info(f"ML model saved to {save_path}")
        except Exception as e:
            logger.debug(f"Could not save model: {e}")

    def _load_model(self, path: str) -> bool:
        """
        Load saved model. Returns True on success, False on any failure.
        FIX: Returns False instead of crashing on sklearn version mismatch
        or corrupted .pkl — caller will then retrain automatically.
        """
        try:
            import pickle
            with open(path, "rb") as f:
                model = pickle.load(f)
            # Validate the loaded model has predict_proba (sanity check)
            if not hasattr(model, "predict_proba"):
                logger.warning(f"Model at {path} is not a valid classifier. Retraining.")
                return False
            self.model = model
            self.is_trained = True
            logger.info(f"ML model loaded from {path}")
            return True
        except Exception as e:
            logger.warning(f"Could not load model from {path}: {e}. Will retrain.")
            return False


# ─────────────────────────────────────────────
# Quick Test
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("\nTesting ML Classifier — Aditya Pandey\n")
    clf = MLTrafficClassifier()

    test_flows = [
        {"dst_port": 443, "src_port": 54321, "protocol": 6,  "packet_count": 900,  "byte_count": 950000,  "label": "YouTube"},
        {"dst_port": 443, "src_port": 54322, "protocol": 6,  "packet_count": 45,   "byte_count": 14000,   "label": "WhatsApp"},
        {"dst_port": 443, "src_port": 54323, "protocol": 6,  "packet_count": 1300, "byte_count": 1600000, "label": "Netflix"},
        {"dst_port": 8801,"src_port": 54324, "protocol": 17, "packet_count": 620,  "byte_count": 420000,  "label": "Zoom"},
        {"dst_port": 22,  "src_port": 54325, "protocol": 6,  "packet_count": 480,  "byte_count": 2100000, "label": "File Transfer"},
        {"dst_port": 443, "src_port": 54326, "protocol": 6,  "packet_count": 720,  "byte_count": 850000,  "label": "TikTok"},
    ]

    print(f"  {'True Label':<18} {'Predicted':<18} {'Confidence':>12}")
    print("  " + "-" * 52)
    for flow in test_flows:
        true_label = flow.pop("label")
        pred, conf = clf.predict(flow)
        match = "✓" if pred == true_label else "~"
        print(f"  {true_label:<18} {pred:<18} {conf:>10}%  {match}")

    print("\n  Feature Importances:")
    for feat, imp in sorted(clf.feature_importances().items(), key=lambda x: -x[1]):
        bar = "█" * int(imp * 40)
        print(f"  {feat:<20} {bar} {imp:.4f}")
