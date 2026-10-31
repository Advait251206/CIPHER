"""
Real-world probe for the phishing URL model (no dataset needed).

PhiUSIIL's legitimate URLs are all bare https://www. homepages, so a model trained on it
can learn "URL has a path => phishing". This script scores a fixed list of legitimate
deep links and phishing patterns with the RAW model (no whitelist, no heuristics) and
with the full service, and writes a CSV plus a summary. Run it before and after
retraining and report both in the paper.

Usage (from backend/):
    python -m training.probe_phishing [--out artifacts/phishing_probe.csv]
"""

import argparse
import csv
import os
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))
os.environ.setdefault("DATABASE_PATH", str(BACKEND / "artifacts" / "probe_tmp.db"))

LEGITIMATE = [
    "https://github.com/Advait251206/CIPHER",
    "https://github.com/scikit-learn/scikit-learn/issues/12345",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://en.wikipedia.org/wiki/Random_forest",
    "https://www.amazon.in/dp/B0CHX1W1XY?ref=ppx_yo2ov_dt_b_product_details&th=1",
    "https://www.sbi.co.in/web/personal-banking",
    "https://www.ugc.gov.in/page/notices",
    "https://mail.google.com/mail/u/0/#inbox",
    "https://stackoverflow.com/questions/231767/what-does-the-yield-keyword-do",
    "https://www.irctc.co.in/nget/train-search",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://arxiv.org/abs/2010.09470",
    "https://www.usenix.org/conference/usenixsecurity22/presentation/arp",
    "https://pypi.org/project/scikit-learn/",
    "https://www.npmjs.com/package/react",
]

PHISHING_PATTERNS = [
    "https://www.paypa1.com",
    "https://paypal-login.xyz",
    "https://www.paypal.com.secure-login-verify.com/",
    "https://accounts-google.com/signin",
    "https://www.microsoft-support-alert.com",
    "https://drive.google.com.evil.top/login",
    "https://sites.google.com/view/paypal-verify-account",
    "http://192.168.1.66/paypal/login.php",
    "https://sbi-kyc-update.top/verify",
    "https://secure-netflix-billing.com/update-payment",
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=str(BACKEND / "artifacts" / "phishing_probe.csv"))
    args = parser.parse_args()

    import warnings
    warnings.filterwarnings("ignore")
    import pandas as pd
    from app.ml.model_loader import ModelLoader
    from app.ml.feature_extractor import FeatureExtractor
    from app.services.phishing_service import PhishingService
    from app.schemas.phishing import PhishingAnalyzeRequest

    loader = ModelLoader()
    if not loader.is_ready:
        print("Phishing model not loaded; train it first.")
        return 1
    names = loader.pipeline["feature_names"]
    fe = FeatureExtractor()
    service = PhishingService()

    rows = []
    for label, urls in (("legitimate", LEGITIMATE), ("phishing", PHISHING_PATTERNS)):
        for url in urls:
            feats = fe.extract_features(fe.canonicalize_url(url))
            raw_p = float(loader.model.predict_proba(pd.DataFrame([feats])[names])[0][1])
            res = service.analyze_url(PhishingAnalyzeRequest(url=url))
            rows.append({
                "true_label": label,
                "url": url,
                "raw_model_p_phish": round(raw_p, 4),
                "service_classification": res.classification,
                "service_risk_score": res.risk_score,
                "decided_by": res.model_version,
            })

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    legit = [r for r in rows if r["true_label"] == "legitimate"]
    phish = [r for r in rows if r["true_label"] == "phishing"]
    raw_fp = sum(r["raw_model_p_phish"] >= 0.5 for r in legit)
    raw_fn = sum(r["raw_model_p_phish"] < 0.5 for r in phish)
    svc_fp = sum(r["service_classification"] == "LIKELY_PHISHING" for r in legit)
    svc_fn = sum(r["service_classification"] == "LEGITIMATE" for r in phish)
    print(f"Model version: {loader.model_version}")
    print(f"Raw model : {raw_fp}/{len(legit)} legitimate URLs flagged, {raw_fn}/{len(phish)} phishing URLs missed")
    print(f"Service   : {svc_fp}/{len(legit)} legitimate URLs LIKELY_PHISHING, {svc_fn}/{len(phish)} phishing URLs LEGITIMATE")
    print(f"Wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
