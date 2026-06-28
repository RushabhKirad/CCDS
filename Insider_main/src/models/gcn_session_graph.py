# -*- coding: utf-8 -*-
"""
GCN Session Graph (LEAKAGE-FREE) -- CERT r4.2 Insider Threat Detection
=======================================================================
Run:  python gcn_session_graph.py

Fix applied: Cross-boundary edges (Sep30 train <-> Oct1 test) are REMOVED.
Only train<->train and test<->test edges are kept, so GCN message passing
cannot bleed future information into training or past labels into test nodes.

Outputs:
  models/gcn_model.pt
  models/gcn_results.json
  gcn_curves.png
  gcn_vs_baseline.png
"""
import os, sys, json, time
import pandas as pd
import numpy as np

def log(msg):
    print(msg); sys.stdout.flush()

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DF_PATH   = os.path.join(PROJECT_ROOT, "data", "processed", "user_day_dataframe_r42.csv")
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
# 1. LOAD + SORT + RESET INDEX
#    CRITICAL: reset_index so that row positions == node IDs in edge_index
# =============================================================================
log("[1/7] Loading and sorting data ...")
df = pd.read_csv(DF_PATH)
df["date"] = pd.to_datetime(df["date"])
df = df.sort_values(["user", "date"]).reset_index(drop=True)
log("      Nodes: {:,}  |  label mean: {:.6f}".format(len(df), df["label"].mean()))

# =============================================================================
# 2. SPLIT MEMBERSHIP (defined first so scaler fits on train only)
# =============================================================================
CUTOFF   = pd.Timestamp("2010-09-30")
is_train = (df["date"] <= CUTOFF).values   # bool array, index-aligned with df
is_test  = (df["date"] >  CUTOFF).values

# =============================================================================
# 3. NODE FEATURES + LABELS
#    Scaler fitted ONLY on train nodes (no test-period statistics leak)
# =============================================================================
log("[2/7] Building node feature tensors ...")
import torch

from sklearn.preprocessing import StandardScaler
scaler   = StandardScaler()
scaler.fit(df.loc[is_train, FEATURES].values)     # fit on train only
X_scaled = scaler.transform(df[FEATURES].values)  # apply to all nodes

x = torch.tensor(X_scaled, dtype=torch.float)
y = torch.tensor(df["label"].values, dtype=torch.long)
log("      x shape: {}  |  y shape: {}".format(x.shape, y.shape))
log("      Scaler fitted on {:,} train nodes only (no test leakage)".format(
    int(is_train.sum())))

# =============================================================================
# 4. BUILD CHRONOLOGICAL EDGES -- NO CROSS-BOUNDARY EDGES
#
#    Rule: only add edge (u, v) if both u and v are in the SAME split.
#    This blocks Sep30(train) <-> Oct1(test) connections that cause
#    temporal leakage via GCN neighborhood aggregation.
# =============================================================================
log("[3/7] Building chronological edges (leak-free) ...")
t0 = time.time()
edge_list = []
cross_blocked = 0

for _, group in df.groupby("user", sort=False):
    idx = group.index.tolist()   # already sorted by date after reset_index
    for i in range(len(idx) - 1):
        u, v = idx[i], idx[i+1]
        # Both in train, or both in test -- never across the boundary
        if (is_train[u] and is_train[v]) or (is_test[u] and is_test[v]):
            edge_list.append([u, v])   # forward
            edge_list.append([v, u])   # backward (undirected)
        else:
            cross_blocked += 1

edge_index = torch.tensor(edge_list, dtype=torch.long).t().contiguous()
log("      Edges kept   : {:,}".format(edge_index.shape[1]))
log("      Cross-boundary edges blocked: {:,}".format(cross_blocked))
log("      Edge build time: {:.1f}s".format(time.time() - t0))

# =============================================================================
# 5. TRAIN / TEST MASKS  (same cutoff used for edge filtering above)
# =============================================================================
log("[4/7] Creating chronological masks ...")
train_mask = torch.tensor(is_train, dtype=torch.bool)
test_mask  = torch.tensor(is_test,  dtype=torch.bool)

log("      Train nodes: {:,}  (malicious: {})".format(
    int(train_mask.sum()), int(y[train_mask].sum())))
log("      Test  nodes: {:,}  (malicious: {})".format(
    int(test_mask.sum()),  int(y[test_mask].sum())))

# =============================================================================
# 5. PyG DATA OBJECT
# =============================================================================
from torch_geometric.data import Data
data = Data(x=x, edge_index=edge_index, y=y,
            train_mask=train_mask, test_mask=test_mask)
log("[5/7] PyG Data: {}".format(data))

# =============================================================================
# 6. GCN MODEL DEFINITION
# =============================================================================
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GCNConv

class GCN(nn.Module):
    def __init__(self, in_channels, hidden_channels=64):
        super().__init__()
        self.conv1   = GCNConv(in_channels, hidden_channels)
        self.conv2   = GCNConv(hidden_channels, 2)
        self.dropout = nn.Dropout(0.3)

    def forward(self, x, edge_index):
        x = self.conv1(x, edge_index)
        x = F.relu(x)
        x = self.dropout(x)
        x = self.conv2(x, edge_index)
        return x   # raw logits, shape [N, 2]

model = GCN(in_channels=len(FEATURES), hidden_channels=64)
log("[6/7] Model: {}".format(model))
total_params = sum(p.numel() for p in model.parameters())
log("      Parameters: {:,}".format(total_params))

# =============================================================================
# 7. CLASS-WEIGHTED LOSS  (critical for 0.41% positive rate)
# =============================================================================
n_total = len(y)
n_pos   = int(y.sum())
n_neg   = n_total - n_pos
pos_weight_val = n_neg / n_pos
log("      Pos weight: {:.1f}  (neg/pos = {}/{})".format(
    pos_weight_val, n_neg, n_pos))

class_weights = torch.tensor([1.0, pos_weight_val], dtype=torch.float)
criterion = nn.CrossEntropyLoss(weight=class_weights)

# =============================================================================
# 8. TRAINING LOOP  (full-batch)
# =============================================================================
log("[7/7] Training for 100 epochs ...")
optimizer = torch.optim.Adam(
    model.parameters(), lr=0.01, weight_decay=5e-4)

EPOCHS = 100
for epoch in range(1, EPOCHS + 1):
    model.train()
    optimizer.zero_grad()
    out  = model(data.x, data.edge_index)
    loss = criterion(out[data.train_mask], data.y[data.train_mask])
    loss.backward()
    optimizer.step()

    if epoch % 10 == 0:
        # Quick train AUC for monitoring
        model.eval()
        with torch.no_grad():
            probs_tr = torch.softmax(out, dim=1)[:, 1].numpy()
        from sklearn.metrics import roc_auc_score
        tr_y = data.y[data.train_mask].numpy()
        tr_p = probs_tr[data.train_mask.numpy()]
        try:
            tr_auc = roc_auc_score(tr_y, tr_p)
        except Exception:
            tr_auc = 0.0
        log("      Epoch {:3d}/{} | loss={:.4f} | train_AUC={:.4f}".format(
            epoch, EPOCHS, float(loss), tr_auc))
        model.train()

# =============================================================================
# 9. EVALUATION ON TEST SET
# =============================================================================
log("\nEvaluating on test set ...")
model.eval()
with torch.no_grad():
    out_all = model(data.x, data.edge_index)
probs_all = torch.softmax(out_all, dim=1)[:, 1].numpy()

# Select test nodes
test_idx   = test_mask.numpy()
y_test     = data.y[test_mask].numpy()
probs_test = probs_all[test_idx]

from sklearn.metrics import (roc_auc_score, average_precision_score,
                              precision_recall_curve, roc_curve,
                              classification_report)

roc_auc = roc_auc_score(y_test, probs_test)
pr_auc  = average_precision_score(y_test, probs_test)
prec, rec, thresh = precision_recall_curve(y_test, probs_test)
f1s     = 2 * prec * rec / (prec + rec + 1e-9)
best_i  = int(np.argmax(f1s))
best_t  = float(thresh[best_i]) if best_i < len(thresh) else float(thresh[-1])
best_f1 = float(f1s[best_i])
best_p  = float(prec[best_i])
best_r  = float(rec[best_i])
y_pred  = (probs_test >= best_t).astype(int)
total_mal = int(y_test.sum())

log("")
log("=" * 60)
log("   GCN RESULTS  --  CERT r4.2 Session Graph")
log("=" * 60)
log("   ROC-AUC              : {:.4f}  [IF baseline: 0.8037]".format(roc_auc))
log("   PR-AUC               : {:.4f}  [IF baseline: 0.0135]".format(pr_auc))
log("   Best F1              : {:.4f}  (thresh={:.4f})".format(best_f1, best_t))
log("   Precision @ best F1  : {:.4f}".format(best_p))
log("   Recall    @ best F1  : {:.4f}".format(best_r))
log("=" * 60)

top_k = {}
for K in [50, 100, 200]:
    idx_k = np.argsort(probs_test)[::-1][:K]
    tp_k  = int(y_test[idx_k].sum())
    top_k[K] = {"tp": tp_k, "prec": round(tp_k/K, 4), "rec": round(tp_k/total_mal, 4)}
    log("   Top-{:3d}: prec={:.3f}  rec={:.3f}  ({}/{})".format(
        K, tp_k/K, tp_k/total_mal, tp_k, K))

log("")
log(classification_report(y_test, y_pred,
                           target_names=["normal","malicious"], digits=4))

# Comparison table
log("COMPARISON vs Isolation Forest:")
log("   Metric        IsoForest    GCN")
log("   ROC-AUC       0.8037       {:.4f}".format(roc_auc))
log("   PR-AUC        0.0135       {:.4f}".format(pr_auc))
log("   Top-100 prec  0.0200       {:.4f}".format(top_k[100]["prec"]))
log("   Best F1       0.0331       {:.4f}".format(best_f1))

# =============================================================================
# PLOTS -- ROC + PR curves, GCN vs Isolation Forest comparison
# =============================================================================
log("\nGenerating plots ...")
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# Load baseline scores for overlay
try:
    baseline = json.load(open(os.path.join(PROJECT_ROOT, "results", "metrics", "baseline_results.json")))
    if_roc   = baseline["roc_auc"]
    if_pr    = baseline["pr_auc"]
except Exception:
    if_roc, if_pr = 0.8037, 0.0135

fpr_gcn, tpr_gcn, _ = roc_curve(y_test, probs_test)

fig, axes = plt.subplots(1, 2, figsize=(16, 6))
fig.patch.set_facecolor("#0f1117")
for ax in axes: ax.set_facecolor("#0f1117")

# ROC
axes[0].plot(fpr_gcn, tpr_gcn, "#f6c90e", lw=2.5,
             label="GCN (AUC={:.3f})".format(roc_auc))
axes[0].axhline(if_roc, color="#3a7bd5", ls="--", lw=1.5, alpha=0.7,
               label="IsoForest (AUC={:.3f})".format(if_roc))
axes[0].plot([0,1],[0,1],"w--",lw=1,alpha=0.3,label="Random")
axes[0].set_xlabel("False Positive Rate", color="white", fontsize=12)
axes[0].set_ylabel("True Positive Rate",  color="white", fontsize=12)
axes[0].set_title("ROC Curve -- GCN vs Isolation Forest",
                   color="white", fontsize=13, fontweight="bold")
axes[0].legend(facecolor="#1a1a2e", labelcolor="white", fontsize=11)
axes[0].tick_params(colors="white")
for sp in axes[0].spines.values(): sp.set_edgecolor("#444")

# PR
axes[1].plot(rec, prec, "#f6c90e", lw=2.5,
             label="GCN (PR-AUC={:.4f})".format(pr_auc))
axes[1].axhline(if_pr, color="#3a7bd5", ls="--", lw=1.5, alpha=0.7,
               label="IsoForest (PR-AUC={:.4f})".format(if_pr))
axes[1].axhline(y_test.mean(), color="white", ls=":", lw=1, alpha=0.4,
               label="Random ({:.4f})".format(y_test.mean()))
axes[1].scatter([best_r],[best_p], color="#ff6b6b", zorder=5, s=140,
               label="Best F1={:.3f}".format(best_f1))
axes[1].set_xlabel("Recall",    color="white", fontsize=12)
axes[1].set_ylabel("Precision", color="white", fontsize=12)
axes[1].set_title("Precision-Recall Curve -- GCN vs Isolation Forest",
                   color="white", fontsize=13, fontweight="bold")
axes[1].legend(facecolor="#1a1a2e", labelcolor="white", fontsize=11)
axes[1].tick_params(colors="white")
for sp in axes[1].spines.values(): sp.set_edgecolor("#444")

plt.tight_layout(pad=1.8)
pp = os.path.join(PROJECT_ROOT, "results", "figures", "gcn_curves.png")
plt.savefig(pp, dpi=150, facecolor=fig.get_facecolor()); plt.close()
log("Plot saved: " + pp)

# Bar comparison chart
fig2, axes2 = plt.subplots(1, 3, figsize=(14, 5))
fig2.patch.set_facecolor("#0f1117")
metrics_names  = ["ROC-AUC", "PR-AUC x10", "Top-100 Prec"]
if_vals  = [if_roc, if_pr * 10, 0.020]
gcn_vals = [roc_auc, pr_auc * 10, top_k[100]["prec"]]

for i, (ax, name, iv, gv) in enumerate(zip(axes2, metrics_names, if_vals, gcn_vals)):
    ax.set_facecolor("#0f1117")
    bars = ax.bar(["IsoForest","GCN"], [iv, gv],
                  color=["#3a7bd5","#f6c90e"], width=0.5)
    ax.set_title(name, color="white", fontsize=12, fontweight="bold")
    ax.tick_params(colors="white")
    ax.set_ylim(0, max(iv,gv)*1.35)
    for bar, val in zip(bars, [iv, gv]):
        ax.text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.001,
                "{:.3f}".format(val), ha="center", va="bottom",
                color="white", fontsize=11, fontweight="bold")
    for sp in ax.spines.values(): sp.set_edgecolor("#444")
    ax.yaxis.label.set_color("white")

fig2.suptitle("GCN vs Isolation Forest -- CERT r4.2",
              color="white", fontsize=15, fontweight="bold")
plt.tight_layout(pad=1.5)
pp2 = os.path.join(PROJECT_ROOT, "results", "figures", "gcn_vs_baseline.png")
fig2.patch.set_facecolor("#0f1117")
plt.savefig(pp2, dpi=150, facecolor=fig2.get_facecolor()); plt.close()
log("Comparison chart saved: " + pp2)

# =============================================================================
# SAVE MODEL + RESULTS
# =============================================================================
torch.save(model.state_dict(), os.path.join(MODEL_DIR, "gcn_model.pt"))
results = dict(
    model                 = "GCN_2layer_LeakageFree",
    leakage_fix           = "cross-boundary edges removed",
    cross_edges_blocked   = cross_blocked,
    hidden_channels       = 64,
    epochs                = EPOCHS,
    train_nodes           = int(train_mask.sum()),
    test_nodes            = int(test_mask.sum()),
    test_malicious        = total_mal,
    total_edges           = int(edge_index.shape[1]),
    roc_auc               = round(roc_auc, 4),
    pr_auc                = round(pr_auc, 4),
    best_f1               = round(best_f1, 4),
    precision_at_best_f1  = round(best_p, 4),
    recall_at_best_f1     = round(best_r, 4),
    top50_prec            = top_k[50]["prec"],
    top100_prec           = top_k[100]["prec"],
    top200_prec           = top_k[200]["prec"],
    improvement_roc_auc   = round(roc_auc - if_roc, 4),
    improvement_pr_auc    = round(pr_auc - if_pr, 4),
    features              = FEATURES,
)
rp = os.path.join(PROJECT_ROOT, "results", "metrics", "gcn_results.json")
with open(rp, "w") as f: json.dump(results, f, indent=2)
log("Model   saved: " + os.path.join(MODEL_DIR, "gcn_model.pt"))
log("Results saved: " + rp)
log("\nALL DONE.")
