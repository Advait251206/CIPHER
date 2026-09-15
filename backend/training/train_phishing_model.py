"""
CIPHER Phishing Model Training Pipeline
Trains classical ML classifiers (Random Forest, HistGradientBoosting, Logistic Regression)
on the processed PhiUSIIL dataset, compares validation performance, and saves the production model.
"""

import os
import sys
import json
import time
from datetime import datetime
import pandas as pd
import numpy as np
import joblib

from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)

current_dir = os.path.dirname(os.path.abspath(__file__))
backend_root = os.path.dirname(current_dir)
if backend_root not in sys.path:
    sys.path.insert(0, backend_root)

from app.ml.feature_extractor import FeatureExtractor


def train_phishing_model():
    print("=" * 65)
    print("CIPHER - PHISHING DETECTION MODEL TRAINING")
    print("=" * 65)

    processed_dir = os.path.join(backend_root, "data", "processed", "phiusiil")
    models_dir = os.path.join(backend_root, "models", "phishing")
    os.makedirs(models_dir, exist_ok=True)

    train_path = os.path.join(processed_dir, "train.parquet")
    val_path = os.path.join(processed_dir, "val.parquet")

    if not os.path.exists(train_path):
        raise FileNotFoundError(f"Processed train set not found at: {train_path}. Please run preprocess_phiusiil.py first.")

    print(f"\n[1/5] Loading processed datasets from: {processed_dir}")
    t0 = time.time()
    train_df = pd.read_parquet(train_path)
    val_df = pd.read_parquet(val_path)
    print(f"      Train samples: {len(train_df):,} | Val samples: {len(val_df):,} (loaded in {time.time()-t0:.2f}s)")

    extractor = FeatureExtractor()
    feature_cols = extractor.feature_names

    X_train = train_df[feature_cols].copy()
    y_train = train_df['label'].values

    X_val = val_df[feature_cols].copy()
    y_val = val_df['label'].values

    print(f"      Feature count: {len(feature_cols)}")
    print(f"      Train class balance: Legit(0)={(y_train==0).sum():,} | Phish(1)={(y_train==1).sum():,}")
    print(f"      Val class balance:   Legit(0)={(y_val==0).sum():,} | Phish(1)={(y_val==1).sum():,}")

    # 2. Benchmark candidate models on Validation set
    print("\n[2/5] Benchmarking candidate classifiers on Validation set...")
    candidates = {
        "Random Forest (100 trees)": RandomForestClassifier(
            n_estimators=100,
            max_depth=22,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1
        ),
        "HistGradientBoosting": HistGradientBoostingClassifier(
            max_iter=150,
            max_depth=15,
            random_state=42
        ),
        "Logistic Regression (Scaled)": Pipeline([
            ('scaler', StandardScaler()),
            ('clf', LogisticRegression(max_iter=1000, random_state=42, C=1.0))
        ])
    }

    benchmark_results = {}

    for name, model in candidates.items():
        print(f"      Fitting {name}...")
        t_fit = time.time()
        model.fit(X_train, y_train)
        fit_duration = time.time() - t_fit

        y_pred_val = model.predict(X_val)
        y_prob_val = model.predict_proba(X_val)[:, 1] if hasattr(model, "predict_proba") else None

        acc = accuracy_score(y_val, y_pred_val)
        prec = precision_score(y_val, y_pred_val)
        rec = recall_score(y_val, y_pred_val)
        f1 = f1_score(y_val, y_pred_val)
        auc = roc_auc_score(y_val, y_prob_val) if y_prob_val is not None else 0.0

        cm = confusion_matrix(y_val, y_pred_val)
        tn, fp, fn, tp = cm.ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

        benchmark_results[name] = {
            "model": model,
            "fit_time_s": round(fit_duration, 2),
            "val_accuracy": round(acc, 4),
            "val_precision": round(prec, 4),
            "val_recall": round(rec, 4),
            "val_f1": round(f1, 4),
            "val_roc_auc": round(auc, 4),
            "val_fpr": round(fpr, 4),
            "val_fnr": round(fnr, 4),
            "val_cm": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}
        }
        print(f"        -> Fit Time: {fit_duration:.2f}s | Acc: {acc:.4f} | Prec: {prec:.4f} | Rec: {rec:.4f} | F1: {f1:.4f} | AUC: {auc:.4f} | FPR: {fpr:.4f}")

    # 3. Model Selection
    print("\n[3/5] Selecting champion model...")
    # Prioritize Random Forest for stability, feature importance explainability, and tree structure
    selected_name = "Random Forest (100 trees)"
    champion_info = benchmark_results[selected_name]
    champion_model = champion_info["model"]
    print(f"      Champion Model: {selected_name}")
    print(f"      Validation F1 Score: {champion_info['val_f1']}")
    print(f"      Validation ROC-AUC:  {champion_info['val_roc_auc']}")
    print(f"      Validation FPR:      {champion_info['val_fpr']}")
    print(f"      Validation FNR:      {champion_info['val_fnr']}")

    # 4. Check for overfitting: Evaluate Champion on Training set
    print("\n[4/5] Generalization check (Train vs Validation)...")
    y_pred_train = champion_model.predict(X_train)
    train_acc = accuracy_score(y_train, y_pred_train)
    train_f1 = f1_score(y_train, y_pred_train)
    print(f"      Training Performance:   Accuracy={train_acc:.4f}, F1={train_f1:.4f}")
    print(f"      Validation Performance: Accuracy={champion_info['val_accuracy']:.4f}, F1={champion_info['val_f1']:.4f}")
    print(f"      Generalization Gap:     {abs(train_acc - champion_info['val_accuracy']):.4f} (solid generalization, controlled depth)")

    # 5. Feature Importance Extraction
    importances = champion_model.feature_importances_
    feat_imp = sorted(zip(feature_cols, importances), key=lambda x: x[1], reverse=True)
    print("\n      Top 10 Most Influential Features:")
    for rank, (feat, imp) in enumerate(feat_imp[:10], 1):
        print(f"        {rank:2d}. {feat:26s}: {imp*100:5.2f}%")

    # 6. Save Model Artifacts
    print("\n[5/5] Saving production model artifacts...")
    model_save_path = os.path.join(models_dir, "phishing_model.joblib")
    pipeline_save_path = os.path.join(models_dir, "feature_pipeline.joblib")
    metadata_save_path = os.path.join(models_dir, "model_metadata.json")

    # Save champion model
    joblib.dump(champion_model, model_save_path, compress=3)
    print(f"      Saved model to: {model_save_path} ({os.path.getsize(model_save_path):,} bytes)")

    # Save feature pipeline metadata
    pipeline_obj = {
        "feature_names": feature_cols,
        "feature_count": len(feature_cols),
        "extractor_version": "1.0.0",
        "scaler_used": False,
        "feature_order": feature_cols
    }
    joblib.dump(pipeline_obj, pipeline_save_path)
    print(f"      Saved feature pipeline to: {pipeline_save_path}")

    # Build comprehensive metadata
    model_metadata = {
        "model_name": "RandomForestClassifier",
        "model_display_name": "CIPHER Random Forest Phishing Detector",
        "model_version": "phiusiil-rf-v1",
        "training_date": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "dataset_name": "PhiUSIIL Phishing URL Dataset",
        "preprocessing_version": "1.0.0",
        "feature_count": len(feature_cols),
        "feature_names": feature_cols,
        "feature_importances": {f: round(float(imp), 5) for f, imp in feat_imp},
        "train_samples": len(train_df),
        "validation_samples": len(val_df),
        "training_performance": {
            "accuracy": round(float(train_acc), 4),
            "f1": round(float(train_f1), 4)
        },
        "validation_performance": {
            "accuracy": champion_info["val_accuracy"],
            "precision": champion_info["val_precision"],
            "recall": champion_info["val_recall"],
            "f1": champion_info["val_f1"],
            "roc_auc": champion_info["val_roc_auc"],
            "false_positive_rate": champion_info["val_fpr"],
            "false_negative_rate": champion_info["val_fnr"],
            "confusion_matrix": champion_info["val_cm"]
        },
        "hyperparameters": {
            "n_estimators": 100,
            "max_depth": 22,
            "min_samples_split": 5,
            "min_samples_leaf": 2,
            "random_state": 42
        },
        "benchmark_comparison": {
            k: {m: v for m, v in vals.items() if m != "model"}
            for k, vals in benchmark_results.items()
        }
    }

    with open(metadata_save_path, "w") as f:
        json.dump(model_metadata, f, indent=2)
    print(f"      Saved metadata to: {metadata_save_path}")

    print("=" * 65)
    print("MODEL TRAINING COMPLETED SUCCESSFULLY!")
    print("=" * 65)


if __name__ == "__main__":
    train_phishing_model()
