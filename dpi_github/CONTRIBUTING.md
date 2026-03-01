# Contributing to DPI Engine

Thanks for your interest! Here's how to contribute:

## Setup
```bash
git clone https://github.com/YOUR_USERNAME/dpi-engine.git
cd dpi-engine
python -m venv venv
venv\Scripts\activate  # Windows
pip install -r requirements.txt
```

## Run Tests Before Submitting
```bash
python tests/test_components.py
```

## Areas Open for Contribution
- QUIC/HTTP3 SNI extraction
- More app signatures in `src/app_classifier.py`
- Real PCAP dataset training for ML model
- Docker support
- More unit tests

## Pull Request Guidelines
- One feature/fix per PR
- All 12 tests must pass
- Add your name to contributors if you'd like
