"""
========================================================
  ml/traffic_classifier.py — ML-Based Traffic Classification
  Author   : Aditya Pandey
  Project  : DPI Engine v2.0
  Requires : scikit-learn, pandas, numpy
========================================================

Aditya's design note:
    This is where my AI/ML specialization meets systems programming.

    Traditional DPI relies on SNI (the domain name in TLS).
    But what if SNI is hidden, encrypted, or missing?
    That's where ML comes in.

    Instead of looking at WHAT domain you're connecting to,
    we look at HOW your traffic behaves:
      - Packet sizes
      - Port numbers
      - Flow duration
      - Packet inter-arrival times
      - Protocol patterns

    This is called "traffic fingerprinting" — it's used by
    researchers, network engineers, and security analysts.
    Each application has a distinctive "shape" to its traffic.

    Pipeline:
        [Flow Features] → [Feature Extraction] → [ML Model] → [App Label]

    Model: Random Forest Classifier
        - Handles mixed feature types well
        - Interpretable (feature importance)
        - Fast inference
        - Good with small training sets
        - Industry standard for traffic classification research
"""

import os
import sys
import json
import logging
import pickle
import numpy as np
from pathlib import Path
from typing import Optional, List, Tuple, Dict

sys.path.insert(0, str(Path(__file__).parent.parent))

logger = logging.getLogger("MLClassifier")

MODEL_PATH = Path(__file__).parent / "model.pkl"
LABEL_PATH = Path(__file__).parent / "labels.json"


# ─────────────────────────────────────────────
# Feature Extraction
# ─────────────────────────────────────────────

class FlowFeatureExtractor:
    """
    Extracts numerical features from a network flow for ML classification.

    Feature Set (12 features):
        [0]  dst_port              — destination port number
        [1]  protocol              — 6=TCP, 17=UDP
        [2]  payload_size_mean     — avg payload bytes per packet
        [3]  payload_size_std      — std dev of payload sizes
        [4]  payload_size_max      — max payload in flow
        [5]  payload_size_min      — min payload in flow
        [6]  packet_count          — total packets in flow
        [7]  byte_count            — total bytes in flow
        [8]  flow_duration         — seconds from first to last packet
        [9]  packets_per_second    — throughput rate
        [10] bytes_per_second      — data rate
        [11] is_port_443           — binary: 1 if HTTPS port
        [12] is_port_80            — binary: 1 if HTTP port
        [13] is_port_53            — binary: 1 if DNS

    Why these features?
        - Ports reveal the service category (443=HTTPS, 53=DNS, etc.)
        - Payload stats capture the "signature" of each app
          (video streaming has large, regular packets; DNS has tiny ones)
        - Flow-level stats (duration, rate) reveal behavioral patterns
    """

    FEATURE_NAMES = [
        "dst_port", "protocol",
        "payload_mean", "payload_std", "payload_max", "payload_min",
        "pkt_count", "byte_count", "duration",
        "pkts_per_sec", "bytes_per_sec",
        "is_port_443", "is_port_80", "is_port_53"
    ]

    def extract(self, flow_data: dict) -> np.ndarray:
        """
        Extract feature vector from a flow data dictionary.

        flow_data keys:
            dst_port, protocol, payload_sizes (list),
            packet_count, byte_count, duration
        """
        dst_port      = flow_data.get("dst_port", 0)
        protocol      = flow_data.get("protocol", 6)
        payload_sizes = flow_data.get("payload_sizes", [0])
        pkt_count     = flow_data.get("packet_count", 1)
        byte_count    = flow_data.get("byte_count", 0)
        duration      = max(flow_data.get("duration", 0.001), 0.001)

        sizes = np.array(payload_sizes) if payload_sizes else np.array([0])

        features = [
            dst_port,
            protocol,
            float(np.mean(sizes)),
            float(np.std(sizes))   if len(sizes) > 1 else 0.0,
            float(np.max(sizes)),
            float(np.min(sizes)),
            pkt_count,
            byte_count,
            duration,
            pkt_count / duration,
            byte_count / duration,
            1.0 if dst_port == 443 else 0.0,
            1.0 if dst_port == 80  else 0.0,
            1.0 if dst_port == 53  else 0.0,
        ]

        return np.array(features, dtype=np.float32)

    def extract_batch(self, flows: List[dict]) -> np.ndarray:
        return np.vstack([self.extract(f) for f in flows])


# ─────────────────────────────────────────────
# Training Data Generator
# ─────────────────────────────────────────────

class TrainingDataGenerator:
    """
    Generates synthetic but realistic training data for the ML model.

    In production you'd use labeled PCAP files.
    For demonstration, we generate data based on known traffic patterns
    from network research papers and empirical observation.

    Aditya's note:
        This is a simplified training set. A production model would
        use thousands of real labeled flows. The architecture is
        identical — only the data source changes.
    """

    import random as _random

    # App traffic profiles: (port, protocol, typical_payload_range, pkt_count_range)
    APP_PROFILES = {
        "YouTube":    {"ports":[443],    "proto":6,  "payload":(800,1400), "pkts":(20,200),  "duration":(5,60)},
        "Netflix":    {"ports":[443],    "proto":6,  "payload":(900,1450), "pkts":(30,300),  "duration":(10,120)},
        "WhatsApp":   {"ports":[443,5222],"proto":6, "payload":(50,500),   "pkts":(5,50),    "duration":(0.5,10)},
        "TikTok":     {"ports":[443],    "proto":6,  "payload":(700,1400), "pkts":(15,150),  "duration":(3,30)},
        "GitHub":     {"ports":[443,22], "proto":6,  "payload":(200,900),  "pkts":(5,40),    "duration":(0.2,5)},
        "Discord":    {"ports":[443,50005],"proto":6,"payload":(100,600),  "pkts":(10,80),   "duration":(1,30)},
        "Zoom":       {"ports":[443,8801],"proto":17,"payload":(400,1200), "pkts":(50,500),  "duration":(60,3600)},
        "Spotify":    {"ports":[443,4070],"proto":6, "payload":(500,1000), "pkts":(20,100),  "duration":(5,300)},
        "DNS":        {"ports":[53],     "proto":17, "payload":(20,512),   "pkts":(1,4),     "duration":(0.01,0.5)},
        "HTTP":       {"ports":[80],     "proto":6,  "payload":(100,1400), "pkts":(3,30),    "duration":(0.1,3)},
    }

    def generate(self, samples_per_class: int = 150) -> Tuple[np.ndarray, List[str]]:
        """Generate synthetic training data."""
        import random
        extractor = FlowFeatureExtractor()
        X, y = [], []

        for app, profile in self.APP_PROFILES.items():
            for _ in range(samples_per_class):
                port     = random.choice(profile["ports"])
                proto    = profile["proto"]
                n_pkts   = random.randint(*profile["pkts"])
                duration = random.uniform(*profile["duration"])
                payloads = [random.randint(*profile["payload"]) for _ in range(n_pkts)]
                # Add realistic noise
                payloads = [max(0, p + random.randint(-50, 50)) for p in payloads]

                flow = {
                    "dst_port"    : port,
                    "protocol"    : proto,
                    "payload_sizes": payloads,
                    "packet_count": n_pkts,
                    "byte_count"  : sum(payloads),
                    "duration"    : duration
                }
                X.append(extractor.extract(flow))
                y.append(app)

        return np.vstack(X), y


# ─────────────────────────────────────────────
# ML Classifier
# ─────────────────────────────────────────────

class MLTrafficClassifier:
    """
    Random Forest classifier for network traffic app identification.

    Aditya's note:
        Random Forest is ideal here because:
        1. Handles the mixed numeric feature set well
        2. Robust to outliers (noisy network data)
        3. Gives feature importance — you can see WHICH
           features drive classification (interpretable)
        4. No need for feature scaling (unlike SVM, KNN)
        5. Fast training and fast inference

        In future work, this could be upgraded to:
        - LSTM for sequential packet pattern learning
        - Gradient Boosting (XGBoost) for higher accuracy
        - A neural network trained on raw packet bytes
    """

    def __init__(self):
        self.model     = None
        self.labels    = []
        self.extractor = FlowFeatureExtractor()
        self.trained   = False

    def train(self, X: np.ndarray, y: List[str], verbose: bool = True):
        """Train the Random Forest model."""
        try:
            from sklearn.ensemble         import RandomForestClassifier
            from sklearn.model_selection  import cross_val_score
            from sklearn.preprocessing    import LabelEncoder
        except ImportError:
            raise RuntimeError(
                "scikit-learn required.\n"
                "Install: pip install scikit-learn pandas numpy"
            )

        if verbose:
            print(f"\n  [ML] Training on {len(X)} samples, {len(set(y))} classes...")

        self.model = RandomForestClassifier(
            n_estimators = 100,
            max_depth    = 12,
            random_state = 42,
            n_jobs       = -1       # use all CPU cores
        )
        self.model.fit(X, y)
        self.labels  = sorted(set(y))
        self.trained = True

        if verbose:
            scores = cross_val_score(self.model, X, y, cv=5, scoring="accuracy")
            print(f"  [ML] Cross-validation accuracy: {scores.mean()*100:.1f}% ± {scores.std()*100:.1f}%")
            print(f"  [ML] Classes: {self.labels}")
            self._print_feature_importance()

    def _print_feature_importance(self):
        if not self.model:
            return
        importances = self.model.feature_importances_
        names       = FlowFeatureExtractor.FEATURE_NAMES
        ranked      = sorted(zip(names, importances), key=lambda x: -x[1])
        print("\n  [ML] Top Feature Importances:")
        for name, imp in ranked[:6]:
            bar = "█" * int(imp * 40)
            print(f"       {name:<20} {bar} {imp:.3f}")

    def predict(self, flow_data: dict) -> Tuple[str, float]:
        """
        Predict app from flow features.
        Returns (predicted_app, confidence_score).
        """
        if not self.trained:
            return "Unknown", 0.0

        features = self.extractor.extract(flow_data).reshape(1, -1)
        pred     = self.model.predict(features)[0]
        proba    = self.model.predict_proba(features)[0]
        conf     = float(max(proba))
        return pred, conf

    def predict_batch(self, flows: List[dict]) -> List[Tuple[str, float]]:
        """Predict multiple flows at once."""
        if not self.trained or not flows:
            return [("Unknown", 0.0)] * len(flows)
        X    = self.extractor.extract_batch(flows)
        preds = self.model.predict(X)
        probas = self.model.predict_proba(X)
        return [(p, float(max(pr))) for p, pr in zip(preds, probas)]

    def save(self, path: str = None):
        """Save trained model to disk."""
        path = path or str(MODEL_PATH)
        with open(path, "wb") as f:
            pickle.dump(self.model, f)
        with open(str(LABEL_PATH), "w") as f:
            json.dump(self.labels, f)
        logger.info(f"Model saved to {path}")

    def load(self, path: str = None) -> bool:
        """Load model from disk."""
        path = path or str(MODEL_PATH)
        if not Path(path).exists():
            return False
        try:
            with open(path, "rb") as f:
                self.model = pickle.load(f)
            with open(str(LABEL_PATH)) as f:
                self.labels = json.load(f)
            self.trained = True
            logger.info(f"Model loaded: {len(self.labels)} classes")
            return True
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return False


# ─────────────────────────────────────────────
# CLI / Demo
# ─────────────────────────────────────────────

def train_and_demo():
    """Train the model on synthetic data and show predictions."""
    print("\n" + "="*55)
    print("  DPI Engine — ML Traffic Classifier")
    print("  Author: Aditya Pandey")
    print("="*55)

    # Generate training data
    print("\n  [1/3] Generating synthetic training data...")
    gen = TrainingDataGenerator()
    X, y = gen.generate(samples_per_class=150)
    print(f"        {len(X)} flows, {len(set(y))} app classes")

    # Train
    print("\n  [2/3] Training Random Forest classifier...")
    clf = MLTrafficClassifier()
    clf.train(X, y, verbose=True)

    # Save
    clf.save()
    print(f"\n  [3/3] Model saved to ml/model.pkl")

    # Demo predictions
    print("\n  [DEMO] Predicting unseen flows:")
    print(f"\n  {'Flow Description':<30} {'Predicted App':<15} {'Confidence'}")
    print("  " + "-"*55)

    test_flows = [
        ("Large HTTPS flow (streaming?)",  {"dst_port":443,"protocol":6, "payload_sizes":[1200]*50,"packet_count":50,"byte_count":60000,"duration":15}),
        ("Tiny UDP bursts (DNS?)",          {"dst_port":53, "protocol":17,"payload_sizes":[60]*3,  "packet_count":3, "byte_count":180,  "duration":0.05}),
        ("Mid HTTP flow",                   {"dst_port":80, "protocol":6, "payload_sizes":[400]*8, "packet_count":8, "byte_count":3200, "duration":0.8}),
        ("High-rate video stream",          {"dst_port":443,"protocol":6, "payload_sizes":[1350]*120,"packet_count":120,"byte_count":162000,"duration":30}),
        ("Short HTTPS burst (API?)",        {"dst_port":443,"protocol":6, "payload_sizes":[250]*6, "packet_count":6, "byte_count":1500, "duration":0.3}),
        ("Long UDP session (VoIP?)",        {"dst_port":8801,"protocol":17,"payload_sizes":[800]*200,"packet_count":200,"byte_count":160000,"duration":120}),
    ]

    for desc, flow in test_flows:
        app, conf = clf.predict(flow)
        bar = "▓" * int(conf * 20)
        print(f"  {desc:<30} {app:<15} {bar} {conf*100:.0f}%")

    print(f"\n  Model is ready. Integrate with DPI Engine for hybrid detection.")
    print(f"  Next step: replace synthetic data with labeled PCAP flows for higher accuracy.\n")


if __name__ == "__main__":
    train_and_demo()
