"""
CIPHER - Network Intrusion Detection Model Training Pipeline
Trains binary (BENIGN vs ATTACK) and multiclass (9 categories) Random Forest models
on CIC-IDS2017 processed Parquet datasets with complete evaluation, feature importance,
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
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, confusion_matrix,
    classification_report
)

current_dir = os.path.dirname(os.path.abspath(__file__))
backend_root = os.path.dirname(current_dir)
if backend_root not in sys.path:
    sys.path.insert(0, backend_root)


class NetworkFeaturePipeline:
    """
    Guarantees strict feature ordering, NaN/Inf sanitization,
    and type conversion for network flow features.
    """
    def __init__(self, feature_names):
        self.feature_names = list(feature_names)
        self.feature_count = len(self.feature_names)
        self.medians = {}

    def fit(self, X):
        if isinstance(X, pd.DataFrame):
            for col in self.feature_names:
                if col in X.columns:
                    val = float(X[col].median())
                    self.medians[col] = 0.0 if np.isnan(val) else val
                else:
                    self.medians[col] = 0.0
        return self

    def transform(self, X):
        if isinstance(X, dict):
            # Single flow dict -> DataFrame
            X = pd.DataFrame([X])

        if isinstance(X, pd.DataFrame):
            # Ensure all required features exist, filling missing with medians
            df_out = pd.DataFrame(index=X.index)
            for col in self.feature_names:
                if col in X.columns:
                    df_out[col] = X[col]
                else:
                    df_out[col] = self.medians.get(col, 0.0)

            # Sanitize Infs and NaNs
            arr = df_out.values.astype(np.float32)
            pos_mask = np.isposinf(arr)
            neg_mask = np.isneginf(arr)
            nan_mask = np.isnan(arr)
            arr[pos_mask] = 1e6
            arr[neg_mask] = 0.0
            arr[nan_mask] = 0.0
            return arr
        elif isinstance(X, np.ndarray):
            arr = np.nan_to_num(X.astype(np.float32), nan=0.0, posinf=1e6, neginf=0.0)
            return arr
        else:
            raise ValueError(f"Unsupported input type for transform: {type(X)}")


def train_network_ids():
    print("=" * 75)
    print("CIPHER - NETWORK IDS MODEL TRAINING & EVALUATION (CIC-IDS2017)")
    print("=" * 75)

    data_dir = os.path.join(backend_root, "data", "processed", "cic_ids2017")
    models_dir = os.path.join(backend_root, "models", "network")
    os.makedirs(models_dir, exist_ok=True)

    meta_path = os.path.join(data_dir, "metadata", "preprocessing_metadata.json")
    with open(meta_path, "r", encoding="utf-8") as f:
        prep_metadata = json.load(f)

    feature_names = prep_metadata["feature_names"]
    multiclass_classes = prep_metadata["multiclass_classes"]
    class_to_idx = prep_metadata["class_to_idx"]
    idx_to_class = {idx: cls for cls, idx in class_to_idx.items()}

    print(f"\nFeatures ({len(feature_names)}): {feature_names[:5]} ... {feature_names[-3:]}")
    print(f"Classes ({len(multiclass_classes)}): {multiclass_classes}")

    # 1. Load Parquet Data
    print("\n[1/6] Loading Train, Validation, and Held-Out Test Parquet partitions...")
    t0 = time.time()
    train_df = pd.read_parquet(os.path.join(data_dir, "train", "train.parquet"))
    val_df = pd.read_parquet(os.path.join(data_dir, "validation", "val.parquet"))
    test_df = pd.read_parquet(os.path.join(data_dir, "test", "test.parquet"))
    print(f"      Train: {len(train_df):,} | Val: {len(val_df):,} | Test: {len(test_df):,} ({time.time()-t0:.2f}s)")

    # 2. Fit Feature Pipeline
    print("\n[2/6] Fitting Network Feature Pipeline...")
    pipeline = NetworkFeaturePipeline(feature_names)
    pipeline.fit(train_df[feature_names])

    X_train = pipeline.transform(train_df[feature_names])
    y_train_binary = train_df["is_attack"].values.astype(np.int32)
    y_train_multi = train_df["attack_category"].map(class_to_idx).values.astype(np.int32)

    X_val = pipeline.transform(val_df[feature_names])
    y_val_binary = val_df["is_attack"].values.astype(np.int32)
    y_val_multi = val_df["attack_category"].map(class_to_idx).values.astype(np.int32)

    X_test = pipeline.transform(test_df[feature_names])
    y_test_binary = test_df["is_attack"].values.astype(np.int32)
    y_test_multi = test_df["attack_category"].map(class_to_idx).values.astype(np.int32)

    # 3. Train Binary Random Forest
    print("\n[3/6] Training Binary Random Forest Classifier (BENIGN vs ATTACK)...")
    t_bin_start = time.time()
    rf_binary = RandomForestClassifier(
        n_estimators=100,
        max_depth=24,
        min_samples_leaf=2,
        max_features="sqrt",
        n_jobs=-1,
        random_state=42,
        verbose=0
    )
    rf_binary.fit(X_train, y_train_binary)
    bin_duration = time.time() - t_bin_start
    print(f"      Binary RF trained in {bin_duration:.2f}s")

    # 4. Train Multiclass Random Forest
    print("\n[4/6] Training Multiclass Random Forest Classifier (9 Attack Categories)...")
    t_multi_start = time.time()
    rf_multiclass = RandomForestClassifier(
        n_estimators=100,
        max_depth=24,
        min_samples_leaf=2,
        max_features="sqrt",
        n_jobs=-1,
        random_state=42,
        verbose=0
    )
    rf_multiclass.fit(X_train, y_train_multi)
    multi_duration = time.time() - t_multi_start
    print(f"      Multiclass RF trained in {multi_duration:.2f}s")

    # 5. Evaluate on Held-Out Test Set
    print("\n[5/6] Comprehensive Evaluation on Held-Out Test Set (374,833 unskewed flows)...")
    
    # Binary Evaluation
    y_test_bin_pred = rf_binary.predict(X_test)
    y_test_bin_prob = rf_binary.predict_proba(X_test)[:, 1]

    bin_acc = float(accuracy_score(y_test_binary, y_test_bin_pred))
    bin_prec = float(precision_score(y_test_binary, y_test_bin_pred, zero_division=0))
    bin_rec = float(recall_score(y_test_binary, y_test_bin_pred, zero_division=0))
    bin_f1 = float(f1_score(y_test_binary, y_test_bin_pred, zero_division=0))
    bin_roc_auc = float(roc_auc_score(y_test_binary, y_test_bin_prob))
    bin_pr_auc = float(average_precision_score(y_test_binary, y_test_bin_prob))

    tn, fp, fn, tp = confusion_matrix(y_test_binary, y_test_bin_pred).ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    print(f"\n--- BINARY METRICS ---")
    print(f"  Accuracy:          {bin_acc*100:.3f}%")
    print(f"  Precision:         {bin_prec*100:.3f}%")
    print(f"  Recall:            {bin_rec*100:.3f}%")
    print(f"  F1-Score:          {bin_f1*100:.3f}%")
    print(f"  ROC-AUC:           {bin_roc_auc:.4f}")
    print(f"  PR-AUC:            {bin_pr_auc:.4f}")
    print(f"  Confusion Matrix:  TN={tn:,}, FP={fp:,}, FN={fn:,}, TP={tp:,}")
    print(f"  False Positive Rate (FPR): {fpr*100:.4f}% ({fp:,} benign flagged as attack)")
    print(f"  False Negative Rate (FNR): {fnr*100:.4f}% ({fn:,} attacks missed)")

    # Multiclass Evaluation
    y_test_multi_pred = rf_multiclass.predict(X_test)
    y_test_multi_prob = rf_multiclass.predict_proba(X_test)

    multi_acc = float(accuracy_score(y_test_multi, y_test_multi_pred))
    multi_f1_macro = float(f1_score(y_test_multi, y_test_multi_pred, average="macro", zero_division=0))
    multi_f1_weighted = float(f1_score(y_test_multi, y_test_multi_pred, average="weighted", zero_division=0))

    cm_multi = confusion_matrix(y_test_multi, y_test_multi_pred, labels=range(len(multiclass_classes)))

    print(f"\n--- MULTICLASS METRICS ---")
    print(f"  Overall Accuracy:    {multi_acc*100:.3f}%")
    print(f"  Macro F1:            {multi_f1_macro*100:.3f}%")
    print(f"  Weighted F1:         {multi_f1_weighted*100:.3f}%")

    report_dict = classification_report(
        y_test_multi,
        y_test_multi_pred,
        target_names=multiclass_classes,
        output_dict=True,
        zero_division=0
    )
    report_text = classification_report(
        y_test_multi,
        y_test_multi_pred,
        target_names=multiclass_classes,
        digits=4,
        zero_division=0
    )
    print("\n" + report_text)

    # Feature Importance (Multiclass & Binary)
    feat_importances = pd.Series(rf_multiclass.feature_importances_, index=feature_names).sort_values(ascending=False)
    top_15_features = {k: float(v) for k, v in feat_importances.head(15).items()}
    print("\n--- TOP 15 IMPORTANT FEATURES ---")
    for feat, imp in top_15_features.items():
        print(f"  {feat:<32}: {imp:.4f}")

    # Realtime Compatibility Classification (Part 13)
    realtime_compatibility = {}
    for feat in feature_names:
        # All extracted flow stats are computable from aggregated packets,
        # but active/idle and long IAT stats require flow termination timeout
        if "Idle" in feat or "Active" in feat:
            realtime_compatibility[feat] = {
                "status": "REALTIME_COMPATIBLE",
                "mode": "FLOW_COMPLETION_REQUIRED",
                "description": "Computed upon flow idle timeout or session termination"
            }
        else:
            realtime_compatibility[feat] = {
                "status": "REALTIME_COMPATIBLE",
                "mode": "STREAMING_COMPUTABLE",
                "description": "Streaming accumulator feature computed during live packet aggregation"
            }

    # 6. Save Artifacts
    print("\n[6/6] Exporting Model Artifacts...")

    # A. Models
    models_dict = {
        "binary_model": rf_binary,
        "multiclass_model": rf_multiclass,
        "feature_names": feature_names,
        "classes": multiclass_classes,
        "class_to_idx": class_to_idx,
        "idx_to_class": idx_to_class
    }
    model_save_path = os.path.join(models_dir, "network_ids_model.joblib")
    joblib.dump(models_dict, model_save_path, compress=3)
    print(f"      Saved Models: {model_save_path} ({os.path.getsize(model_save_path):,} bytes)")

    # B. Feature Pipeline
    pipeline_save_path = os.path.join(models_dir, "network_feature_pipeline.joblib")
    joblib.dump(pipeline, pipeline_save_path)
    print(f"      Saved Pipeline: {pipeline_save_path}")

    # C. Metadata
    metadata = {
        "model_name": "CIPHER Network Intrusion Detection System",
        "model_architecture": "Dual Random Forest (Binary Gate + Multiclass Granular)",
        "framework": "scikit-learn",
        "dataset": "CIC-IDS2017 (MachineLearningCSV)",
        "source_files": [
            "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
            "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
            "Friday-WorkingHours-Morning.pcap_ISCX.csv",
            "Monday-WorkingHours.pcap_ISCX.csv",
            "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
            "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
            "Tuesday-WorkingHours.pcap_ISCX.csv",
            "Wednesday-workingHours.pcap_ISCX.csv"
        ],
        "training_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "split_strategy": prep_metadata["split_strategy"],
        "training_samples": len(train_df),
        "validation_samples": len(val_df),
        "test_samples": len(test_df),
        "feature_count": len(feature_names),
        "feature_names": feature_names,
        "classes": multiclass_classes,
        "class_to_idx": class_to_idx,
        "hyperparameters": {
            "n_estimators": 100,
            "max_depth": 24,
            "min_samples_leaf": 2,
            "max_features": "sqrt",
            "random_state": 42
        },
        "training_duration_seconds": {
            "binary_model": round(bin_duration, 2),
            "multiclass_model": round(multi_duration, 2),
            "total": round(bin_duration + multi_duration, 2)
        },
        "binary_metrics": {
            "accuracy": round(bin_acc, 6),
            "precision": round(bin_prec, 6),
            "recall": round(bin_rec, 6),
            "f1_score": round(bin_f1, 6),
            "roc_auc": round(bin_roc_auc, 6),
            "pr_auc": round(bin_pr_auc, 6),
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp),
            "false_positive_rate": round(fpr, 6),
            "false_negative_rate": round(fnr, 6)
        },
        "multiclass_metrics": {
            "accuracy": round(multi_acc, 6),
            "macro_f1": round(multi_f1_macro, 6),
            "weighted_f1": round(multi_f1_weighted, 6),
            "per_class": report_dict
        },
        "top_15_feature_importances": top_15_features,
        "realtime_feature_compatibility": realtime_compatibility
    }

    meta_save_path = os.path.join(models_dir, "network_model_metadata.json")
    with open(meta_save_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print(f"      Saved Metadata: {meta_save_path}")

    # D. Evaluation Report Text
    report_file_path = os.path.join(models_dir, "network_evaluation_report.txt")
    with open(report_file_path, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("CIPHER NETWORK INTRUSION DETECTION SYSTEM - EVALUATION REPORT\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"Model Architecture: Dual Random Forest (Binary + Multiclass)\n")
        f.write(f"Dataset:            CIC-IDS2017 (MachineLearningCSV)\n")
        f.write(f"Evaluated Samples:  {len(test_df):,} held-out test flows (15% unskewed)\n")
        f.write(f"Split Strategy:     {prep_metadata['split_strategy']}\n")
        f.write(f"Features:           {len(feature_names)} numerical flow features\n\n")
        f.write("-" * 80 + "\n")
        f.write("1. BINARY CLASSIFICATION METRICS (BENIGN vs ATTACK)\n")
        f.write("-" * 80 + "\n")
        f.write(f"Accuracy:                  {bin_acc*100:.4f}%\n")
        f.write(f"Precision:                 {bin_prec*100:.4f}%\n")
        f.write(f"Recall:                    {bin_rec*100:.4f}%\n")
        f.write(f"F1-Score:                  {bin_f1*100:.4f}%\n")
        f.write(f"ROC-AUC:                   {bin_roc_auc:.5f}\n")
        f.write(f"PR-AUC:                    {bin_pr_auc:.5f}\n")
        f.write(f"Confusion Matrix:          TN={tn:,}, FP={fp:,}, FN={fn:,}, TP={tp:,}\n")
        f.write(f"False Positive Rate (FPR): {fpr*100:.4f}% ({fp:,} benign flows misclassified as attack)\n")
        f.write(f"False Negative Rate (FNR): {fnr*100:.4f}% ({fn:,} attack flows misclassified as benign)\n\n")
        f.write("-" * 80 + "\n")
        f.write("2. MULTICLASS CLASSIFICATION REPORT (9 TAXONOMY CATEGORIES)\n")
        f.write("-" * 80 + "\n")
        f.write(report_text + "\n\n")
        f.write("-" * 80 + "\n")
        f.write("3. TOP 20 FEATURE IMPORTANCES\n")
        f.write("-" * 80 + "\n")
        for i, (feat, val) in enumerate(feat_importances.head(20).items(), 1):
            f.write(f"{i:2d}. {feat:<35}: {val:.5f}\n")
        f.write("\n" + "=" * 80 + "\n")
    print(f"      Saved Report: {report_file_path}")

    # E. Confusion Matrix Visualizations (Binary and Multiclass)
    cm_img_path = os.path.join(models_dir, "confusion_matrix.png")
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(18, 7))

    # Binary CM
    bin_cm = np.array([[tn, fp], [fn, tp]])
    im1 = ax1.imshow(bin_cm, interpolation='nearest', cmap=plt.cm.Blues)
    ax1.set_title("CIPHER Binary IDS Confusion Matrix\n(BENIGN vs ATTACK)", fontsize=13, fontweight="bold")
    plt.colorbar(im1, ax=ax1, fraction=0.046, pad=0.04)
    tick_marks_bin = np.arange(2)
    ax1.set_xticks(tick_marks_bin)
    ax1.set_xticklabels(["BENIGN", "ATTACK"])
    ax1.set_yticks(tick_marks_bin)
    ax1.set_yticklabels(["BENIGN", "ATTACK"])
    ax1.set_ylabel("True Label", fontweight="bold")
    ax1.set_xlabel("Predicted Label", fontweight="bold")
    thresh_bin = bin_cm.max() / 2.
    for i in range(2):
        for j in range(2):
            ax1.text(j, i, f"{bin_cm[i, j]:,}",
                     horizontalalignment="center",
                     color="white" if bin_cm[i, j] > thresh_bin else "black",
                     fontweight="bold")

    # Multiclass CM
    im2 = ax2.imshow(cm_multi, interpolation='nearest', cmap=plt.cm.Greens)
    ax2.set_title("CIPHER Multiclass IDS Confusion Matrix\n(9 Attack Categories)", fontsize=13, fontweight="bold")
    plt.colorbar(im2, ax=ax2, fraction=0.046, pad=0.04)
    tick_marks_multi = np.arange(len(multiclass_classes))
    ax2.set_xticks(tick_marks_multi)
    ax2.set_xticklabels(multiclass_classes, rotation=45, ha="right", fontsize=9)
    ax2.set_yticks(tick_marks_multi)
    ax2.set_yticklabels(multiclass_classes, fontsize=9)
    ax2.set_ylabel("True Label", fontweight="bold")
    ax2.set_xlabel("Predicted Label", fontweight="bold")
    thresh_multi = cm_multi.max() / 2.
    for i in range(len(multiclass_classes)):
        for j in range(len(multiclass_classes)):
            val = cm_multi[i, j]
            if val > 0:
                ax2.text(j, i, f"{val:,}" if val > 1000 else f"{val}",
                         horizontalalignment="center",
                         fontsize=8,
                         color="white" if val > thresh_multi else "black")

    plt.tight_layout()
    plt.savefig(cm_img_path, dpi=200, bbox_inches="tight")
    plt.close()
    print(f"      Saved Confusion Matrix Plot: {cm_img_path}")

    print("=" * 75)
    print("NETWORK IDS TRAINING & EVALUATION COMPLETE!")
    print("=" * 75)


if __name__ == "__main__":
    train_network_ids()
