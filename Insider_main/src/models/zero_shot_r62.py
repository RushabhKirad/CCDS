# -*- coding: utf-8 -*-
"""
Zero-Shot Evaluation: r4.2-Trained GCN applied to r6.2 Graph
"""
import os
import torch
import torch.nn.functional as F
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score, average_precision_score, precision_recall_curve, auc
import torch_geometric
from torch_geometric.data import Data
from torch_geometric.nn import GCNConv

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
R62_DATA  = os.path.join(PROJECT_ROOT, "data", "processed", "user_day_dataframe_v62.csv")
R42_DATA  = os.path.join(PROJECT_ROOT, "data", "processed", "user_day_dataframe_r42.csv")
MODEL_WT  = os.path.join(PROJECT_ROOT, "models", "gcn_model.pt")

FEATURES = [
    "logon_count", "after_hours_flag", "unique_pc_count", 
    "usb_connect_count", "usb_disconnect_count", "usb_first_time_flag",
    "files_copied", "exe_copied_flag", 
    "emails_sent", "external_email_ratio",
    "http_visit_count", "job_site_visits", "suspicious_url_visits"
]

def log(m): print(m)

# ── 1. Load GCN Model Definition ──
class GCN(torch.nn.Module):
    def __init__(self, in_channels, hidden_channels=64):
        super().__init__()
        self.conv1   = GCNConv(in_channels, hidden_channels)
        self.conv2   = GCNConv(hidden_channels, 2)
        self.dropout = torch.nn.Dropout(0.3)

    def forward(self, x, edge_index):
        x = self.conv1(x, edge_index)
        x = F.relu(x)
        x = self.dropout(x)
        x = self.conv2(x, edge_index)
        return x

# ── 2. Load r4.2 Data strictly to get the properly fitted Scaler ──
log("Fitting scaler using r4.2 training data strictly...")
df_42 = pd.read_csv(R42_DATA)
df_42["date_dt"] = pd.to_datetime(df_42["date"])
cutoff_42 = pd.to_datetime("2010-09-30")
train_mask_42 = (df_42["date_dt"] < cutoff_42).values

scaler = StandardScaler()
# Fit ONLY on r4.2 train set as we did during model training
scaler.fit(df_42[train_mask_42][FEATURES].values)
del df_42

# ── 3. Load r6.2 Dataset ──
log("Loading r6.2 dataset...")
df_62 = pd.read_csv(R62_DATA)

# Apply r4.2 scaler (Zero-Shot)
x_62_arr = scaler.transform(df_62[FEATURES].values)
x_62 = torch.tensor(x_62_arr, dtype=torch.float)
y_62 = torch.tensor(df_62["label"].values, dtype=torch.long)
users_62 = df_62["user"].values

# ── 4. Build r6.2 Edges (Chronological User Chains) ──
log("Building r6.2 chronological graph...")
edge_list = []
for u, group in df_62.groupby("user", sort=False):
    idx = group.index.tolist()
    for i in range(len(idx) - 1):
        edge_list.append([idx[i], idx[i+1]])
        edge_list.append([idx[i+1], idx[i]])

edge_index_62 = torch.tensor(edge_list, dtype=torch.long).t().contiguous()
if edge_index_62.numel() == 0:
    edge_index_62 = torch.empty((2, 0), dtype=torch.long)

data_62 = Data(x=x_62, edge_index=edge_index_62, y=y_62)

# ── 5. Run Inference ──
log("Running Zero-Shot Inference using r4.2 weights...")
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
model = GCN(in_channels=len(FEATURES)).to(device)
model.load_state_dict(torch.load(MODEL_WT, map_location=device))
model.eval()
data_62 = data_62.to(device)

with torch.no_grad():
    out = model(data_62.x, data_62.edge_index)
    probs = F.softmax(out, dim=1)[:, 1].cpu().numpy()

# ── 6. Metrics Calculation ──
labels = y_62.cpu().numpy()

# Session-Level Metrics
roc_auc_session = roc_auc_score(labels, probs)
pr_auc_session  = average_precision_score(labels, probs)

# User-Level Metrics (Critical for Sparse Regimes)
df_62["raw_score"] = probs
df_62["is_malicious"] = labels

log("\n==================================")
log("  r4.2 -> r6.2 ZERO-SHOT RESULTS")
log("==================================")
log(f"Session-Level ROC-AUC : {roc_auc_session:.4f}")
log(f"Session-Level PR-AUC  : {pr_auc_session:.4f} (Base Rate: {labels.mean():.6f})")

# Group by user and take the MAXIMUM anomaly score they generated in any session
user_agg = df_62.groupby("user").agg(
    max_score=("raw_score", "max"),
    is_malicious=("is_malicious", "max") 
).reset_index()

user_agg = user_agg.sort_values(by="max_score", ascending=False).reset_index(drop=True)

roc_auc_user = roc_auc_score(user_agg["is_malicious"], user_agg["max_score"])
log(f"User-Level ROC-AUC    : {roc_auc_user:.4f}")

# Recall@K Calculation
total_insiders = int(user_agg["is_malicious"].sum())
log(f"\nUser-Level Detection (Total Insiders: {total_insiders}):")

insider_ranks = user_agg[user_agg["is_malicious"] == 1].index.tolist()
insider_ranks = [r + 1 for r in insider_ranks] # 1-indexed rank

k_values = [10, 20, 50, 100, 200, 400]
for k in k_values:
    caught = sum(1 for r in insider_ranks if r <= k)
    log(f"  Recall@{k:<3} : {caught}/{total_insiders} ({caught/total_insiders*100:.1f}%)")

log("\nTop 5 Highest Scoring Users:")
for i, row in user_agg.head(5).iterrows():
    flag = " [MALICIOUS INSIDER]" if row["is_malicious"] == 1 else ""
    log(f"  Rank {i+1}: {row['user']} - Score: {row['max_score']:.4f}{flag}")

log("\nInsider Ranks:")
for r in sorted(insider_ranks):
    log(f"  Rank {r}")

