"""
CIPHER Email Phishing Model Training & Benchmark Pipeline
Evaluates candidate classifiers (Random Forest, HistGradientBoosting, Logistic Regression)
on the validation set, selects the optimal architecture, fits on the training set,
and comprehensively evaluates on the held-out test set with ROC-AUC, PR-AUC,
confusion matrix plotting, and metadata generation.
"""

import os
import sys
import json
import time
import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, confusion_matrix,
    classification_report
)

current_dir = os.path.dirname(os.path.abspath(__file__))
backend_root = os.path.dirname(current_dir)
if backend_root not in sys.path:
    sys.path.insert(0, backend_root)

from app.ml.email_feature_extractor import EmailFeaturePipeline



def train_email_model():
    print("=" * 80)
    print("CIPHER PHASE 12 — EMAIL PHISHING MODEL BENCHMARKING & TRAINING")
    print("=" * 80)

    data_dir = os.path.join(backend_root, "data", "processed", "email_phishing")
    models_dir = os.path.join(backend_root, "models", "email")
    os.makedirs(models_dir, exist_ok=True)

    meta_path = os.path.join(data_dir, "metadata", "email_preprocessing_metadata.json")
    with open(meta_path, "r", encoding="utf-8") as f:
        prep_meta = json.load(f)

    feature_names = prep_meta["feature_names"]
    print(f"\n[1/5] Ingesting Parquet splits with {len(feature_names)} features...")
    train_df = pd.read_parquet(os.path.join(data_dir, "train.parquet"))
    val_df = pd.read_parquet(os.path.join(data_dir, "val.parquet"))
    test_df = pd.read_parquet(os.path.join(data_dir, "test.parquet"))

    X_train_raw = train_df[feature_names]
    y_train = train_df["label"].values.astype(int)

    X_val_raw = val_df[feature_names]
    y_val = val_df["label"].values.astype(int)

    X_test_raw = test_df[feature_names]
    y_test = test_df["label"].values.astype(int)

    print(f"      - Training samples:   {len(X_train_raw):,}")
    print(f"      - Validation samples: {len(X_val_raw):,}")
    print(f"      - Held-out samples:   {len(X_test_raw):,}")

    # Fit feature pipeline
    pipeline = EmailFeaturePipeline(feature_names)
    pipeline.fit(X_train_raw)
    X_train = pipeline.transform(X_train_raw)
    X_val = pipeline.transform(X_val_raw)
    X_test = pipeline.transform(X_test_raw)

    # [2/5] Benchmarking candidate architectures
    print("\n[2/5] Benchmarking candidate classifiers on Validation split...")
    candidates = {
        "Random Forest (100 trees, depth=20)": RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_leaf=2,
            max_features="sqrt",
            n_jobs=-1,
            random_state=42
        ),
        "HistGradientBoosting": HistGradientBoostingClassifier(
            max_iter=100,
            random_state=42
        ),
        "Logistic Regression (L2, Scaled)": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(max_iter=1000, random_state=42))
        ])
    }

    bench_results = {}
    best_name = None
    best_f1 = -1.0
    best_model = None

    for name, clf in candidates.items():
        t0 = time.time()
        clf.fit(X_train, y_train)
        fit_time = time.time() - t0

        y_pred = clf.predict(X_val)
        y_prob = clf.predict_proba(X_val)[:, 1] if hasattr(clf, "predict_proba") else y_pred

        acc = float(accuracy_score(y_val, y_pred))
        prec = float(precision_score(y_val, y_pred, zero_division=0))
        rec = float(recall_score(y_val, y_pred, zero_division=0))
        f1 = float(f1_score(y_val, y_pred, zero_division=0))
        auc = float(roc_auc_score(y_val, y_prob))
        pr_auc = float(average_precision_score(y_val, y_prob))
        tn, fp, fn, tp = confusion_matrix(y_val, y_pred).ravel()

        bench_results[name] = {
            "fit_time_s": round(fit_time, 2),
            "val_accuracy": round(acc, 4),
            "val_precision": round(prec, 4),
            "val_recall": round(rec, 4),
            "val_f1": round(f1, 4),
            "val_roc_auc": round(auc, 4),
            "val_pr_auc": round(pr_auc, 4),
            "val_fp": int(fp),
            "val_fn": int(fn)
        }

        print(f"      * {name:38s} | Fit: {fit_time:5.2f}s | Acc: {acc*100:6.2f}% | F1: {f1*100:6.2f}% | AUC: {auc:6.4f} | FP: {fp:4d} | FN: {fn:4d}")

        if f1 > best_f1:
            best_f1 = f1
            best_name = name
            best_model = clf

    print(f"\n      Selected Top Architecture: [{best_name}] (Validation F1 = {best_f1*100:.2f}%)")

    # [3/5] Test Set Evaluation
    print(f"\n[3/5] Comprehensive Evaluation of Selected Model on Held-Out Test Set ({len(X_test):,} samples)...")
    t_test_eval = time.time()
    y_test_pred = best_model.predict(X_test)
    y_test_prob = best_model.predict_proba(X_test)[:, 1] if hasattr(best_model, "predict_proba") else y_test_pred
    test_eval_time = time.time() - t_test_eval

    test_acc = float(accuracy_score(y_test, y_test_pred))
    test_prec = float(precision_score(y_test, y_test_pred, zero_division=0))
    test_rec = float(recall_score(y_test, y_test_pred, zero_division=0))
    test_f1 = float(f1_score(y_test, y_test_pred, zero_division=0))
    test_roc_auc = float(roc_auc_score(y_test, y_test_prob))
    test_pr_auc = float(average_precision_score(y_test, y_test_prob))

    tn, fp, fn, tp = confusion_matrix(y_test, y_test_pred).ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
    throughput = float(len(X_test) / test_eval_time) if test_eval_time > 0 else 0.0

    print("\n--- HELD-OUT TEST PERFORMANCE ---")
    print(f"  Accuracy:                  {test_acc*100:.3f}%")
    print(f"  Precision:                 {test_prec*100:.3f}%")
    print(f"  Recall:                    {test_rec*100:.3f}%")
    print(f"  F1-Score:                  {test_f1*100:.3f}%")
    print(f"  ROC-AUC:                   {test_roc_auc:.4f}")
    print(f"  PR-AUC:                    {test_pr_auc:.4f}")
    print(f"  Confusion Matrix:          TN={tn:,}, FP={fp:,}, FN={fn:,}, TP={tp:,}")
    print(f"  False Positive Rate (FPR): {fpr*100:.4f}% ({fp:,} benign emails flagged)")
    print(f"  False Negative Rate (FNR): {fnr*100:.4f}% ({fn:,} malicious emails missed)")
    print(f"  Inference Throughput:      {throughput:,.1f} emails/sec")

    # Classification report
    rep = classification_report(y_test, y_test_pred, target_names=["BENIGN", "MALICIOUS"], digits=4)
    print("\n" + rep)

    # Feature Importance (if Random Forest or tree-based)
    feature_importances = {}
    if hasattr(best_model, "feature_importances_"):
        fis = best_model.feature_importances_
        sorted_indices = np.argsort(fis)[::-1]
        for idx in sorted_indices:
            feature_importances[feature_names[idx]] = round(float(fis[idx]), 5)
        print("\nTop 10 Feature Importances:")
        for k, v in list(feature_importances.items())[:10]:
            print(f"  - {k:30s}: {v:.5f}")

    # [4/5] Confusion Matrix Plotting
    print("\n[4/5] Generating Confusion Matrix Visualization...")
    cm_path = os.path.join(models_dir, "confusion_matrix.png")
    fig, ax = plt.subplots(figsize=(6, 5))
    cm = np.array([[tn, fp], [fn, tp]])
    im = ax.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
    ax.figure.colorbar(im, ax=ax)
    classes = ["BENIGN", "MALICIOUS"]
    ax.set(xticks=np.arange(cm.shape[1]),
           yticks=np.arange(cm.shape[0]),
           xticklabels=classes, yticklabels=classes,
           title="CIPHER Email Phishing - Test Confusion Matrix",
           ylabel="True Label",
           xlabel="Predicted Label")
    thresh = cm.max() / 2.
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(j, i, f"{cm[i, j]:,}",
                    ha="center", va="center",
                    color="white" if cm[i, j] > thresh else "black",
                    fontweight="bold")
    fig.tight_layout()
    fig.savefig(cm_path, dpi=200)
    plt.close(fig)
    print(f"      Saved: {cm_path}")

    # [5/5] Serialization & Metadata
    print("\n[5/5] Serializing model artifact and metadata...")
    model_path = os.path.join(models_dir, "email_phishing_model.joblib")
    pipeline_path = os.path.join(models_dir, "email_feature_pipeline.joblib")

    joblib.dump(best_model, model_path, compress=3)
    joblib.dump(pipeline, pipeline_path, compress=3)

    metadata = {
        "model_name": best_name,
        "model_version": "cipher-email-rf-v1",
        "training_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "dataset_name": "Kaggle Phishing Email Multi-Corpus Aggregation",
        "source_corpora": prep_meta["dataset_sources"],
        "feature_count": len(feature_names),
        "feature_names": feature_names,
        "feature_importances": feature_importances,
        "split_strategy": prep_meta["split_strategy"],
        "train_samples": len(X_train),
        "val_samples": len(X_val),
        "test_samples": len(X_test),
        "benchmark_comparison": bench_results,
        "test_metrics": {
            "accuracy": round(test_acc, 6),
            "precision": round(test_prec, 6),
            "recall": round(test_rec, 6),
            "f1_score": round(test_f1, 6),
            "roc_auc": round(test_roc_auc, 6),
            "pr_auc": round(test_pr_auc, 6),
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp),
            "false_positive_rate": round(fpr, 6),
            "false_negative_rate": round(fnr, 6),
            "throughput_emails_per_sec": round(throughput, 1)
        }
    }

    meta_out_path = os.path.join(models_dir, "email_model_metadata.json")
    with open(meta_out_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    report_path = os.path.join(models_dir, "email_evaluation_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("CIPHER EMAIL PHISHING MODEL EVALUATION REPORT\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"Selected Architecture: {best_name}\n")
        f.write(f"Training Date:         {metadata['training_timestamp']}\n")
        f.write(f"Features Extracted:    {len(feature_names)}\n\n")
        f.write("HELD-OUT TEST SET METRICS (12,359 unskewed samples):\n")
        f.write(f"  Accuracy:          {test_acc*100:.3f}%\n")
        f.write(f"  Precision:         {test_prec*100:.3f}%\n")
        f.write(f"  Recall:            {test_rec*100:.3f}%\n")
        f.write(f"  F1-Score:          {test_f1*100:.3f}%\n")
        f.write(f"  ROC-AUC:           {test_roc_auc:.4f}\n")
        f.write(f"  PR-AUC:            {test_pr_auc:.4f}\n")
        f.write(f"  Confusion Matrix:  TN={tn:,}, FP={fp:,}, FN={fn:,}, TP={tp:,}\n")
        f.write(f"  False Positive Rate: {fpr*100:.4f}% ({fp:,} benign emails flagged)\n")
        f.write(f"  False Negative Rate: {fnr*100:.4f}% ({fn:,} malicious emails missed)\n")
        f.write(f"  Throughput:        {throughput:,.1f} emails/s\n\n")
        f.write("CLASSIFICATION REPORT:\n")
        f.write(rep + "\n")

    print(f"      - Saved: {model_path} ({os.path.getsize(model_path):,} bytes)")
    print(f"      - Saved: {pipeline_path}")
    print(f"      - Saved: {meta_out_path}")
    print(f"      - Saved: {report_path}")
    print("\nTraining & evaluation completed successfully!")


if __name__ == "__main__":
    train_email_model()
