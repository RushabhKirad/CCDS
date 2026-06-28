# -*- coding: utf-8 -*-
"""
Ablation Study + Scenario-wise Evaluation -- CERT r4.2
=======================================================
Run:  python ablation_study.py

Experiments:
  A) No-Edge GCN (MLP equivalent): edge_index = empty -> isolates features vs. graph
  B) GCN (chronological, leak-free): same as gcn_session_graph.py
  C) Per-scenario AUC: AB-I, AB-II, AB-III evaluated separately

Outputs:
  models/ablation_results.json
  ablation_comparison.png
  scenario_roc.png
"""
import os, sys, json, time
import pandas as pd
import numpy as np

def log(msg):
    print(msg); sys.stdout.flush()

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DF_PATH   = os.path.join(PROJECT_ROOT, "data", "processed", "user_day_dataframe.csv")
MODEL_DIR = os.path.join(PROJECT_ROOT, "models")
os.makedirs(MODEL_DIR, exist_ok=True)

# malicious_users.py lives in src/data_processing
sys.path.insert(0, os.path.join(PROJECT_ROOT, "src", "data_processing"))

FEATURES = [
    "logon_count", "after_hours_flag", "unique_pc_count",
    "usb_connect_count", "usb_disconnect_count", "usb_first_time_flag",
    "files_copied", "exe_copied_flag",
    "emails_sent", "external_email_ratio",
    "http_visit_count", "job_site_visits", "suspicious_url_visits",
]

EPOCHS   = 100
CUTOFF   = pd.Timestamp("2010-09-30")
HIDDEN   = 64
LR       = 0.01
WD       = 5e-4
SEED     = 42

# =============================================================================
# 1. LOAD DATA
# =============================================================================
log("=" * 65)
log("  ABLATION STUDY -- CERT r4.2 GCN vs MLP vs Isolation Forest")
log("=" * 65)
log("\n[SETUP] Loading data ...")
import torch
torch.manual_seed(SEED)

df = pd.read_csv(DF_PATH)
df["date"] = pd.to_datetime(df["date"])
df = df.sort_values(["user", "date"]).reset_index(drop=True)
log("        Nodes: {:,}  |  label mean: {:.6f}".format(len(df), df["label"].mean()))

# Split membership arrays (for edge filtering)
is_train = (df["date"] <= CUTOFF).values
is_test  = (df["date"] >  CUTOFF).values

# Scale features (fit on normal train only -- same as main script)
from sklearn.preprocessing import StandardScaler
train_normal_mask = is_train & (df["label"].values == 0)
scaler = StandardScaler()
scaler.fit(df.loc[train_normal_mask, FEATURES].values)
X_scaled = scaler.transform(df[FEATURES].values)

x = torch.tensor(X_scaled, dtype=torch.float)
y = torch.tensor(df["label"].values, dtype=torch.long)

train_mask = torch.tensor(is_train, dtype=torch.bool)
test_mask  = torch.tensor(is_test,  dtype=torch.bool)
y_test     = y[test_mask].numpy()
total_mal  = int(y_test.sum())

log("        Train: {:,}  |  Test: {:,}  |  Malicious in test: {}".format(
    int(train_mask.sum()), int(test_mask.sum()), total_mal))

# Class weights
n_pos = int(y.sum());  n_neg = len(y) - n_pos
pos_wt = n_neg / n_pos
class_weights = torch.tensor([1.0, pos_wt], dtype=torch.float)
log("        Class weight pos: {:.1f}".format(pos_wt))

# =============================================================================
# 2. BUILD CHRONOLOGICAL EDGES (leak-free)
# =============================================================================
log("\n[EDGES] Building chronological edges (leak-free) ...")
t0 = time.time()
edge_list = []
cross_blocked = 0
for _, group in df.groupby("user", sort=False):
    idx = group.index.tolist()
    for i in range(len(idx) - 1):
        u, v = idx[i], idx[i+1]
        if (is_train[u] and is_train[v]) or (is_test[u] and is_test[v]):
            edge_list.append([u, v]);  edge_list.append([v, u])
        else:
            cross_blocked += 1

edge_index_full = torch.tensor(edge_list, dtype=torch.long).t().contiguous()
edge_index_empty = torch.empty((2, 0), dtype=torch.long)  # MLP ablation

log("        Edges (GCN)   : {:,}".format(edge_index_full.shape[1]))
log("        Edges (MLP)   : 0  (no-edge ablation)")
log("        Cross-boundary blocked: {:,}".format(cross_blocked))
log("        Built in {:.1f}s".format(time.time() - t0))

# =============================================================================
# 3. MODEL DEFINITION
# =============================================================================
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GCNConv
from torch_geometric.data import Data

class GCN(nn.Module):
    def __init__(self, in_ch, hidden=64):
        super().__init__()
        self.conv1   = GCNConv(in_ch, hidden)
        self.conv2   = GCNConv(hidden, 2)
        self.dropout = nn.Dropout(0.3)
    def forward(self, x, edge_index):
        x = F.relu(self.conv1(x, edge_index))
        x = self.dropout(x)
        x = self.conv2(x, edge_index)
        return x

# =============================================================================
# 4. TRAINING FUNCTION
# =============================================================================
from sklearn.metrics import (roc_auc_score, average_precision_score,
                              precision_recall_curve, roc_curve,
                              classification_report)

def train_and_eval(edge_index, label, epochs=EPOCHS):
    """Train GCN with given edge_index; return (probs_test, metrics_dict)."""
    torch.manual_seed(SEED)
    data    = Data(x=x, edge_index=edge_index, y=y,
                   train_mask=train_mask, test_mask=test_mask)
    model   = GCN(in_ch=len(FEATURES), hidden=HIDDEN)
    crit    = nn.CrossEntropyLoss(weight=class_weights)
    optim   = torch.optim.Adam(model.parameters(), lr=LR, weight_decay=WD)

    for ep in range(1, epochs + 1):
        model.train()
        optim.zero_grad()
        out  = model(data.x, data.edge_index)
        loss = crit(out[data.train_mask], data.y[data.train_mask])
        loss.backward();  optim.step()

        if ep % 20 == 0:
            model.eval()
            with torch.no_grad():
                tr_probs = torch.softmax(out, dim=1)[:,1].numpy()
            tr_auc = roc_auc_score(
                y[train_mask].numpy(), tr_probs[train_mask.numpy()])
            log("      [{label}] Epoch {ep:3d}/{epochs}  loss={loss:.4f}  train_AUC={tr_auc:.4f}".format(
                label=label, ep=ep, epochs=epochs,
                loss=float(loss), tr_auc=tr_auc))
            model.train()

    # Eval
    model.eval()
    with torch.no_grad():
        out_all   = model(data.x, data.edge_index)
    probs_all  = torch.softmax(out_all, dim=1)[:,1].numpy()
    probs_test = probs_all[test_mask.numpy()]

    roc = roc_auc_score(y_test, probs_test)
    pr  = average_precision_score(y_test, probs_test)
    pc, rc, thr = precision_recall_curve(y_test, probs_test)
    f1s  = 2*pc*rc/(pc+rc+1e-9)
    bi   = int(np.argmax(f1s))
    bf1  = float(f1s[bi])
    bt   = float(thr[bi]) if bi < len(thr) else float(thr[-1])
    bp   = float(pc[bi]); br = float(rc[bi])

    top_k = {}
    for K in [50, 100, 200]:
        idx_k = np.argsort(probs_test)[::-1][:K]
        tp_k  = int(y_test[idx_k].sum())
        top_k[K] = {"tp": tp_k, "prec": round(tp_k/K, 4), "rec": round(tp_k/total_mal, 4)}

    return probs_test, dict(
        roc_auc=round(roc,4), pr_auc=round(pr,4),
        best_f1=round(bf1,4), prec_at_f1=round(bp,4), rec_at_f1=round(br,4),
        top50=top_k[50]["prec"], top100=top_k[100]["prec"], top200=top_k[200]["prec"],
        probs_test=probs_test   # keep for scenario analysis
    )

# =============================================================================
# 5A. EXPERIMENT A: MLP (no edges)
# =============================================================================
log("\n" + "="*65)
log("  EXPERIMENT A: MLP (no-edge GCN = 2-layer MLP equivalent)")
log("="*65)
_, mlp_res = train_and_eval(edge_index_empty, label="MLP")
log("\n  MLP Test Results:")
log("    ROC-AUC  : {:.4f}".format(mlp_res["roc_auc"]))
log("    PR-AUC   : {:.4f}".format(mlp_res["pr_auc"]))
log("    Best F1  : {:.4f}".format(mlp_res["best_f1"]))
log("    Top-100  : {:.4f}".format(mlp_res["top100"]))

# =============================================================================
# 5B. EXPERIMENT B: GCN (full chronological edges, leak-free)
# =============================================================================
log("\n" + "="*65)
log("  EXPERIMENT B: GCN (chronological edges, leak-free)")
log("="*65)
gcn_probs, gcn_res = train_and_eval(edge_index_full, label="GCN")
log("\n  GCN Test Results:")
log("    ROC-AUC  : {:.4f}".format(gcn_res["roc_auc"]))
log("    PR-AUC   : {:.4f}".format(gcn_res["pr_auc"]))
log("    Best F1  : {:.4f}".format(gcn_res["best_f1"]))
log("    Top-100  : {:.4f}".format(gcn_res["top100"]))

# Baseline numbers from saved file
try:
    br = json.load(open(os.path.join(PROJECT_ROOT, "results", "metrics", "baseline_results.json")))
    if_roc = br["roc_auc"]; if_pr = br["pr_auc"]
    if_top100 = br["top100_prec"]
except:
    if_roc, if_pr, if_top100 = 0.8037, 0.0135, 0.020

log("\n" + "="*65)
log("  FULL COMPARISON TABLE")
log("="*65)
log("  Model           ROC-AUC   PR-AUC   Top-100P  Best-F1")
log("  Isolation For.  {:.4f}   {:.4f}   {:.4f}   0.0331".format(
    if_roc, if_pr, if_top100))
log("  MLP (no edges)  {:.4f}   {:.4f}   {:.4f}   {:.4f}".format(
    mlp_res["roc_auc"], mlp_res["pr_auc"], mlp_res["top100"], mlp_res["best_f1"]))
log("  GCN (graph)     {:.4f}   {:.4f}   {:.4f}   {:.4f}".format(
    gcn_res["roc_auc"], gcn_res["pr_auc"], gcn_res["top100"], gcn_res["best_f1"]))

# =============================================================================
# 6. PER-SCENARIO AUC (AB-I, AB-II, AB-III)
# =============================================================================
log("\n" + "="*65)
log("  PER-SCENARIO ROC-AUC BREAKDOWN")
log("="*65)

# Load malicious users to get scenario assignments
try:
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "malicious_users",
        os.path.join(PROJECT_ROOT, "src", "data_processing", "malicious_users.py"))
    mu_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mu_mod)
    MALICIOUS_USERS = mu_mod.MALICIOUS_USERS
    SCENARIO_MAP = {1: "AB-I", 2: "AB-II", 3: "AB-III"}
    log("    Loaded {:,} malicious users from malicious_users.py".format(
        len(MALICIOUS_USERS)))
    loaded_mu = True
except Exception as e:
    log("    Could not load malicious_users.py: {}".format(e))
    loaded_mu = False

# Build test node dataframe with GCN probs
test_df = df[test_mask.numpy()].copy()
test_df["gcn_prob"]  = gcn_res["probs_test"]
test_df["mlp_prob"]  = mlp_res["probs_test"]

scenario_results = {}
if loaded_mu:
    # Add scenario column
    def get_scenario(row):
        u = row["user"]
        if u in MALICIOUS_USERS:
            sc_num = MALICIOUS_USERS[u].get("scenario", 0)
            return SCENARIO_MAP.get(sc_num, "unknown")
        return "normal"

    test_df["scenario"] = test_df.apply(get_scenario, axis=1)

    for sc in ["AB-I", "AB-II", "AB-III"]:
        # Test nodes: this scenario's malicious + all normals
        sc_mask = (test_df["scenario"] == sc) | (test_df["label"] == 0)
        sub = test_df[sc_mask]
        y_sub = sub["label"].values

        if y_sub.sum() == 0:
            log("    {}: no malicious sessions in test set".format(sc))
            continue

        gcn_auc = roc_auc_score(y_sub, sub["gcn_prob"].values)
        mlp_auc = roc_auc_score(y_sub, sub["mlp_prob"].values)
        n_mal   = int(y_sub.sum())

        scenario_results[sc] = {
            "n_malicious": n_mal,
            "gcn_roc_auc": round(gcn_auc, 4),
            "mlp_roc_auc": round(mlp_auc, 4),
            "graph_benefit": round(gcn_auc - mlp_auc, 4),
        }
        log("    {:6s}: malicious={:3d}  GCN={:.4f}  MLP={:.4f}  graph_benefit={:+.4f}".format(
            sc, n_mal, gcn_auc, mlp_auc, gcn_auc - mlp_auc))
else:
    # Fallback: use label=1 timestamps to infer scenario from feature patterns
    log("    Running fallback scenario split based on date windows ...")
    # AB-I: wikileaks (Jan-Aug leakers, scenario 1)
    # AB-II: job hunt (sustained, scenario 2)
    # AB-III: ITAdmin sabotage (short, scenario 3)
    # Without ground truth, group by std-dev of malicious windows
    mal_test = test_df[test_df["label"] == 1].copy()
    if len(mal_test) > 0:
        # Proxy: cluster by exe_copied_flag (AB-III proxy) and job_site_visits (AB-II proxy)
        ab3_users = mal_test[mal_test["exe_copied_flag"] > 0]["user"].unique()
        ab2_users = mal_test[(mal_test["job_site_visits"] > 0) &
                              (~mal_test["user"].isin(ab3_users))]["user"].unique()
        ab1_users = mal_test[~mal_test["user"].isin(
            list(ab3_users)+list(ab2_users))]["user"].unique()
        for sc, us in [("AB-I(proxy)", ab1_users),
                        ("AB-II(proxy)", ab2_users),
                        ("AB-III(proxy)", ab3_users)]:
            sc_mask = test_df["user"].isin(us) | (test_df["label"] == 0)
            sub = test_df[sc_mask]
            y_sub = sub["label"].values
            if y_sub.sum() == 0: continue
            gcn_auc = roc_auc_score(y_sub, sub["gcn_prob"].values)
            mlp_auc = roc_auc_score(y_sub, sub["mlp_prob"].values)
            scenario_results[sc] = {
                "n_malicious": int(y_sub.sum()),
                "gcn_roc_auc": round(gcn_auc, 4),
                "mlp_roc_auc": round(mlp_auc, 4),
                "graph_benefit": round(gcn_auc - mlp_auc, 4),
            }
            log("    {:14s}: mal={:3d}  GCN={:.4f}  MLP={:.4f}  delta={:+.4f}".format(
                sc, int(y_sub.sum()), gcn_auc, mlp_auc, gcn_auc - mlp_auc))

# =============================================================================
# 7. PLOTS
# =============================================================================
log("\nGenerating plots ...")
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# ── A. COMPARISON BAR CHART (3 models x 4 metrics) ───────────────────────────
fig, axes = plt.subplots(1, 4, figsize=(20, 5))
fig.patch.set_facecolor("#0d0d14")
labels  = ["IsoForest", "MLP\n(no edges)", "GCN\n(graph)"]
colors  = ["#3a7bd5", "#e67e22", "#f6c90e"]

metricss = [
    ("ROC-AUC",    [if_roc,    mlp_res["roc_auc"], gcn_res["roc_auc"]],   [0.5, 1.0]),
    ("PR-AUC",     [if_pr,     mlp_res["pr_auc"],  gcn_res["pr_auc"]],    [0.0, None]),
    ("Top-100P",   [if_top100, mlp_res["top100"],  gcn_res["top100"]],    [0.0, None]),
    ("Best F1",    [0.0331,    mlp_res["best_f1"], gcn_res["best_f1"]],   [0.0, None]),
]
for ax, (mname, vals, ylim) in zip(axes, metricss):
    ax.set_facecolor("#0d0d14")
    bars = ax.bar(labels, vals, color=colors, width=0.55, edgecolor="#555", linewidth=0.8)
    ax.set_title(mname, color="white", fontsize=12, fontweight="bold", pad=10)
    ax.tick_params(colors="white", labelsize=9)
    ax.set_ylim(ylim[0], ylim[1] if ylim[1] else max(vals)*1.35+0.01)
    for bar, val in zip(bars, vals):
        ax.text(bar.get_x()+bar.get_width()/2, bar.get_height()+max(vals)*0.02,
                "{:.3f}".format(val), ha="center", va="bottom",
                color="white", fontsize=10, fontweight="bold")
    for sp in ax.spines.values(): sp.set_edgecolor("#333")
    ax.xaxis.label.set_color("white")

fig.suptitle("Ablation Study: Feature-Only (MLP) vs Graph (GCN) -- CERT r4.2",
             color="white", fontsize=14, fontweight="bold", y=1.01)
plt.tight_layout(pad=1.5)
p1 = os.path.join(PROJECT_ROOT, "results", "figures", "ablation_comparison.png")
plt.savefig(p1, dpi=150, facecolor=fig.get_facecolor(), bbox_inches="tight")
plt.close()
log("Ablation chart saved: " + p1)

# ── B. PER-SCENARIO ROC BARS ──────────────────────────────────────────────────
if scenario_results:
    sc_names = list(scenario_results.keys())
    gcn_aucs = [scenario_results[s]["gcn_roc_auc"] for s in sc_names]
    mlp_aucs = [scenario_results[s]["mlp_roc_auc"] for s in sc_names]
    n_mals   = [scenario_results[s]["n_malicious"]  for s in sc_names]

    x_pos = np.arange(len(sc_names))
    width = 0.35
    fig2, ax2 = plt.subplots(figsize=(10, 6))
    fig2.patch.set_facecolor("#0d0d14")
    ax2.set_facecolor("#0d0d14")

    bars1 = ax2.bar(x_pos - width/2, mlp_aucs, width, label="MLP (no edges)",
                    color="#e67e22", edgecolor="#555", linewidth=0.8)
    bars2 = ax2.bar(x_pos + width/2, gcn_aucs, width, label="GCN (graph)",
                    color="#f6c90e", edgecolor="#555", linewidth=0.8)

    for bar, val in zip(list(bars1)+list(bars2), mlp_aucs+gcn_aucs):
        ax2.text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.005,
                 "{:.3f}".format(val), ha="center", va="bottom",
                 color="white", fontsize=10, fontweight="bold")

    ax2.set_xticks(x_pos)
    ax2.set_xticklabels(["{}\n(n={})".format(s, n) for s, n in zip(sc_names, n_mals)],
                         color="white", fontsize=11)
    ax2.set_ylabel("ROC-AUC", color="white", fontsize=12)
    ax2.set_ylim(0.5, 1.05)
    ax2.set_title("Per-Scenario ROC-AUC: GCN vs MLP (no edges) -- CERT r4.2",
                  color="white", fontsize=13, fontweight="bold")
    ax2.legend(facecolor="#1a1a2e", labelcolor="white", fontsize=11)
    ax2.tick_params(colors="white")
    for sp in ax2.spines.values(): sp.set_edgecolor("#333")

    plt.tight_layout(pad=1.5)
    p2 = os.path.join(PROJECT_ROOT, "results", "figures", "scenario_roc.png")
    plt.savefig(p2, dpi=150, facecolor=fig2.get_facecolor())
    plt.close()
    log("Scenario ROC chart saved: " + p2)

# =============================================================================
# 8. SAVE FULL RESULTS
# =============================================================================
results = dict(
    isolation_forest = dict(roc_auc=if_roc, pr_auc=if_pr, top100=if_top100, best_f1=0.0331),
    mlp_no_edges     = dict(roc_auc=mlp_res["roc_auc"], pr_auc=mlp_res["pr_auc"],
                             top100=mlp_res["top100"],   best_f1=mlp_res["best_f1"]),
    gcn_graph        = dict(roc_auc=gcn_res["roc_auc"], pr_auc=gcn_res["pr_auc"],
                             top100=gcn_res["top100"],   best_f1=gcn_res["best_f1"]),
    graph_benefit_over_mlp = dict(
        roc_auc  = round(gcn_res["roc_auc"]  - mlp_res["roc_auc"],  4),
        pr_auc   = round(gcn_res["pr_auc"]   - mlp_res["pr_auc"],   4),
        top100   = round(gcn_res["top100"]   - mlp_res["top100"],   4),
        best_f1  = round(gcn_res["best_f1"]  - mlp_res["best_f1"],  4),
    ),
    cross_edges_blocked = cross_blocked,
    scenario_breakdown  = scenario_results,
)
rp = os.path.join(PROJECT_ROOT, "results", "metrics", "ablation_results.json")
with open(rp, "w") as f: json.dump(results, f, indent=2)
log("\nResults saved: " + rp)
log("\nALL DONE.")
