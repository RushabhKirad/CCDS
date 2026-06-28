# -*- coding: utf-8 -*-
"""
Isolation Forest Baseline -- CERT r4.2 Insider Threat Detection
================================================================
Run from the project folder:
    python baseline_isolation_forest.py

Outputs:
    models/isolation_forest.pkl
    models/scaler.pkl
    models/baseline_results.json
    isolation_forest_curves.png
"""
import os, sys, json, joblib
import pandas as pd
import numpy as np

# ── Windows: cap loky workers to avoid deadlock ───────────────────────────────
os.environ["LOKY_MAX_CPU_COUNT"] = "4"

def log(msg):
    """Print with immediate flush so progress shows on Windows."""
    print(msg); sys.stdout.flush()

# ── Paths ─────────────────────────────────────────────────────────────────────
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DF_PATH   = os.path.join(PROJECT_ROOT, "data", "processed", "user_day_dataframe.csv")
MODEL_DIR = os.path.join(PROJECT_ROOT, "models")
os.makedirs(MODEL_DIR, exist_ok=True)

FEATURES = [
    "logon_count", "after_hours_flag", "unique_pc_count",
    "usb_connect_count", "usb_disconnect_count", "usb_first_time_flag",
    "files_copied", "exe_copied_flag",
    "emails_sent", "external_email_ratio",
    "http_visit_count", "job_site_visits", "suspicious_url_visits",
]

# =============================================================================
# 1. LOAD
# =============================================================================
log("[1/6] Loading user_day_dataframe.csv ...")
df = pd.read_csv(DF_PATH)
df["date"] = pd.to_datetime(df["date"])
log("      Rows: {:,}  |  label mean: {:.6f}".format(len(df), df["label"].mean()))

# =============================================================================
# 2. CHRONOLOGICAL SPLIT
#    Train: Jan 2010 -- Sep 2010 (9 months)
#    Test : Oct 2010 -- end      (remaining months)
# =============================================================================
log("[2/6] Chronological split ...")
train_df = df[df["date"] <= "2010-09-30"].copy()
test_df  = df[df["date"] >= "2010-10-01"].copy()

log("      Train: {} sessions  ({} malicious)".format(
    len(train_df), int(train_df["label"].sum())))
log("      Test : {} sessions  ({} malicious)".format(
    len(test_df),  int(test_df["label"].sum())))

# =============================================================================
# 3. STANDARD SCALER -- fit ONLY on normal train sessions
# =============================================================================
log("[3/6] StandardScaler (fit on normal train only) ...")
from sklearn.preprocessing import StandardScaler

train_normal   = train_df[train_df["label"] == 0]
scaler         = StandardScaler()
X_train_normal = scaler.fit_transform(train_normal[FEATURES].values)
X_test         = scaler.transform(test_df[FEATURES].values)
y_test         = test_df["label"].values.astype(int)

log("      Normal train sessions : {:,}".format(len(X_train_normal)))
log("      Test feature matrix   : {}".format(X_test.shape))

# =============================================================================
# 4. ISOLATION FOREST
#    Trained ONLY on normal sessions (unsupervised anomaly detection)
# =============================================================================
log("[4/6] Fitting IsolationForest ...")
from sklearn.ensemble import IsolationForest

iso = IsolationForest(
    n_estimators=100,         # 100 trees -- good trade-off speed / accuracy
    max_samples="auto",       # min(256, n_train) -- fast & memory-safe
    contamination="auto",     # trained on normals -> auto is correct
    random_state=42,
    n_jobs=1,                 # safer on Windows
)
iso.fit(X_train_normal)
log("      Fit done.")

# =============================================================================
# 5. SCORE TEST SET IN SMALL BATCHES
#    Avoids any memory spike; logs progress every 10k rows
# =============================================================================
log("[5/6] Scoring {:,} test sessions in batches ...".format(len(X_test)))
BATCH  = 5000
parts  = []
n_test = len(X_test)
for start in range(0, n_test, BATCH):
    end    = min(start + BATCH, n_test)
    scores = iso.score_samples(X_test[start:end])
    parts.append(scores)
    if (start // BATCH) % 4 == 0:
        log("      ... {}/{} rows scored".format(end, n_test))

# Negate: higher value = more anomalous (easier for AUC/top-K)
anomaly_scores = -np.concatenate(parts)
log("      Score range: [{:.4f}, {:.4f}]".format(
    anomaly_scores.min(), anomaly_scores.max()))

# =============================================================================
# 6. METRICS
# =============================================================================
log("[6/6] Computing metrics ...")
from sklearn.metrics import (roc_auc_score, average_precision_score,
                              precision_recall_curve, roc_curve,
                              classification_report)

roc_auc = roc_auc_score(y_test, anomaly_scores)
pr_auc  = average_precision_score(y_test, anomaly_scores)

prec, rec, thresh = precision_recall_curve(y_test, anomaly_scores)
f1s     = 2 * prec * rec / (prec + rec + 1e-9)
best_i  = int(np.argmax(f1s))
best_t  = float(thresh[best_i]) if best_i < len(thresh) else float(thresh[-1])
best_f1 = float(f1s[best_i])
best_p  = float(prec[best_i])
best_r  = float(rec[best_i])
y_pred  = (anomaly_scores >= best_t).astype(int)
total_mal = int(y_test.sum())

log("")
log("=" * 58)
log("   ISOLATION FOREST BASELINE  --  CERT r4.2")
log("=" * 58)
log("   ROC-AUC              : {:.4f}".format(roc_auc))
log("   PR-AUC               : {:.4f}".format(pr_auc))
log("   Best F1              : {:.4f}  (threshold = {:.4f})".format(best_f1, best_t))
log("   Precision @ best F1  : {:.4f}".format(best_p))
log("   Recall    @ best F1  : {:.4f}".format(best_r))
log("=" * 58)

top_k = {}
log("")
for K in [50, 100, 200]:
    idx   = np.argsort(anomaly_scores)[::-1][:K]
    tp_k  = int(y_test[idx].sum())
    top_k[K] = {"tp": tp_k, "prec": round(tp_k/K, 4), "rec": round(tp_k/total_mal, 4)}
    log("   Top-{:3d}:  precision = {:.3f}   recall = {:.3f}   ({}/{})".format(
        K, tp_k/K, tp_k/total_mal, tp_k, K))

log("")
log(classification_report(y_test, y_pred,
                            target_names=["normal", "malicious"], digits=4))

# Sanity check
if   roc_auc > 0.97: log("WARNING: AUC suspiciously high -- check for leakage!")
elif roc_auc < 0.60: log("WARNING: AUC too low -- check feature quality.")
else:                 log("PASS: ROC-AUC is in expected range (0.60 - 0.97).")

# =============================================================================
# PLOTS  --  ROC + PR side by side
# =============================================================================
log("\nGenerating curves plot ...")
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

fpr, tpr, _ = roc_curve(y_test, anomaly_scores)
fig, axes   = plt.subplots(1, 2, figsize=(16, 6))
fig.patch.set_facecolor("#0f1117")
for ax in axes:
    ax.set_facecolor("#0f1117")

# ROC
axes[0].plot(fpr, tpr, "#3a7bd5", lw=2,
             label="Isolation Forest (AUC = {:.3f})".format(roc_auc))
axes[0].plot([0,1],[0,1], "w--", lw=1, alpha=0.4, label="Random baseline")
axes[0].set_xlabel("False Positive Rate", color="white", fontsize=12)
axes[0].set_ylabel("True Positive Rate",  color="white", fontsize=12)
axes[0].set_title("ROC Curve -- Isolation Forest Baseline",
                   color="white", fontsize=13, fontweight="bold")
axes[0].legend(facecolor="#1a1a2e", labelcolor="white", fontsize=11)
axes[0].tick_params(colors="white")
for sp in axes[0].spines.values(): sp.set_edgecolor("#444")

# PR
axes[1].plot(rec, prec, "#f6c90e", lw=2,
             label="PR-AUC = {:.3f}".format(pr_auc))
axes[1].axhline(y_test.mean(), color="white", ls="--", lw=1, alpha=0.4,
               label="Random ({:.4f})".format(y_test.mean()))
axes[1].scatter([best_r], [best_p], color="#ff6b6b", zorder=5, s=140,
               label="Best F1 = {:.3f}".format(best_f1))
axes[1].set_xlabel("Recall",    color="white", fontsize=12)
axes[1].set_ylabel("Precision", color="white", fontsize=12)
axes[1].set_title("Precision-Recall Curve -- Isolation Forest Baseline",
                   color="white", fontsize=13, fontweight="bold")
axes[1].legend(facecolor="#1a1a2e", labelcolor="white", fontsize=11)
axes[1].tick_params(colors="white")
for sp in axes[1].spines.values(): sp.set_edgecolor("#444")

plt.tight_layout(pad=1.8)
plot_path = os.path.join(PROJECT_ROOT, "results", "figures", "isolation_forest_curves.png")
plt.savefig(plot_path, dpi=150, facecolor=fig.get_facecolor())
plt.close()
log("Plot saved: " + plot_path)

# =============================================================================
# FEATURE SHIFT  --  top-10% anomalous vs rest
# =============================================================================
log("\nFeature shifts (top-10pct anomalous vs rest, in scaled space):")
tmp = pd.DataFrame(X_test, columns=FEATURES)
tmp["hi"] = anomaly_scores >= np.percentile(anomaly_scores, 90)
fi = tmp.groupby("hi")[FEATURES].mean().T
fi.columns = ["low-90pct", "top-10pct"]
fi["diff"]     = fi["top-10pct"] - fi["low-90pct"]
fi["pct_diff"] = (fi["diff"] / (fi["low-90pct"].abs() + 1e-9) * 100).round(1)
log(fi.sort_values("diff", ascending=False).to_string())

# =============================================================================
# SAVE
# =============================================================================
joblib.dump(iso,    os.path.join(MODEL_DIR, "isolation_forest.pkl"))
joblib.dump(scaler, os.path.join(MODEL_DIR, "scaler.pkl"))
log("\nModel  saved : " + os.path.join(MODEL_DIR, "isolation_forest.pkl"))
log("Scaler saved : " + os.path.join(MODEL_DIR, "scaler.pkl"))

results = dict(
    model            = "IsolationForest",
    train_period     = "2010-01-02 to 2010-09-30",
    test_period      = "2010-10-01 to end",
    train_normal     = int(len(X_train_normal)),
    test_total       = int(len(X_test)),
    test_malicious   = total_mal,
    roc_auc          = round(roc_auc, 4),
    pr_auc           = round(pr_auc, 4),
    best_f1          = round(best_f1, 4),
    precision_at_best_f1 = round(best_p, 4),
    recall_at_best_f1    = round(best_r, 4),
    top50_prec       = top_k[50]["prec"],
    top100_prec      = top_k[100]["prec"],
    features         = FEATURES,
)
results_path = os.path.join(PROJECT_ROOT, "results", "metrics", "baseline_results.json")
with open(results_path, "w") as f:
    json.dump(results, f, indent=2)
log("Results saved: " + results_path)
log("\nALL DONE.")
