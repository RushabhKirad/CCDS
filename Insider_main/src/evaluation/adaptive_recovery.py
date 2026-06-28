import os
import torch
import torch.nn.functional as F
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score, average_precision_score, precision_recall_curve, f1_score
from torch_geometric.data import Data
from torch_geometric.nn import GCNConv

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FIG_DIR  = os.path.join(BASE_DIR, "results", "figures")
R42_PATH  = os.path.join(BASE_DIR, "data", "processed", "user_day_dataframe_r42.csv")
R62_PATH  = os.path.join(BASE_DIR, "data", "processed", "user_day_dataframe_v62.csv")
MODEL_WT  = os.path.join(BASE_DIR, "models", "gcn_model.pt")

FEATURES = [
    "logon_count", "after_hours_flag", "unique_pc_count", 
    "usb_connect_count", "usb_disconnect_count", "usb_first_time_flag",
    "files_copied", "exe_copied_flag", 
    "emails_sent", "external_email_ratio",
    "http_visit_count", "job_site_visits", "suspicious_url_visits"
]

def log(m): print(m)

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

def calc_user_metrics(df, score_col, label_col):
    df_eval = df.copy()
    user_agg = df_eval.groupby("user").agg(
        max_score=(score_col, "max"),
        is_malicious=(label_col, "max")
    ).reset_index()
    user_agg = user_agg.sort_values(by="max_score", ascending=False).reset_index(drop=True)
    auc = roc_auc_score(user_agg["is_malicious"], user_agg["max_score"])
    
    total_ins = int(user_agg["is_malicious"].sum())
    insider_ranks = [r + 1 for r in user_agg[user_agg["is_malicious"] == 1].index.tolist()]
    r100 = sum(1 for r in insider_ranks if r <= 100)
    r400 = sum(1 for r in insider_ranks if r <= 400)
    return auc, r100, r400, total_ins

def main():
    log("=== LOADING DATA ===")
    df_62 = pd.read_csv(R62_PATH)
    
    # Needs a fresh r6.2 scaler for Isolation Forest and fine-tuning
    scaler_62 = StandardScaler()
    X_62_arr = scaler_62.fit_transform(df_62[FEATURES].values)
    Y_62 = df_62["label"].values

    df_62["iso_baseline_score"] = 0.0
    df_62["gcn_finetuned_score"] = 0.0

    # 1. Isolation Forest Unsupervised Fallback 
    log("\n=== 1. UNSUPERVISED RECOVERY: ISOLATION FOREST ===")
    iso = IsolationForest(n_estimators=100, contamination=0.001, random_state=42, n_jobs=-1)
    iso.fit(X_62_arr) # Training completely unsupervised on r6.2
    
    # Anomaly scores: lower is more anomalous in sklearn. Invert so high = anomalous.
    raw_iso = iso.decision_function(X_62_arr)
    df_62["iso_score"] = -raw_iso

    iso_auc, iso_r100, iso_r400, tot_ins = calc_user_metrics(df_62, "iso_score", "label")
    log(f"IsoForest User ROC-AUC: {iso_auc:.4f}")
    log(f"IsoForest Recall@100  : {iso_r100}/{tot_ins} ({(iso_r100/tot_ins)*100:.1f}%)")
    log(f"IsoForest Recall@400  : {iso_r400}/{tot_ins} ({(iso_r400/tot_ins)*100:.1f}%)")

    # 2. GCN Fine-Tuning (10% Labeled Adaptation)
    log("\n=== 2. ADAPTIVE RECOVERY: GCN 10% FINE-TUNING ===")
    # Build Edges
    log("Building edges for r6.2...")
    edge_list = []
    for u, group in df_62.groupby("user", sort=False):
        idx = group.index.tolist()
        for i in range(len(idx) - 1):
            edge_list.append([idx[i], idx[i+1]])
            edge_list.append([idx[i+1], idx[i]])

    edge_index_62 = torch.tensor(edge_list, dtype=torch.long).t().contiguous()
    if edge_index_62.numel() == 0:
        edge_index_62 = torch.empty((2, 0), dtype=torch.long)

    x_tensor = torch.tensor(X_62_arr, dtype=torch.float)
    y_tensor = torch.tensor(Y_62, dtype=torch.long)
    data = Data(x=x_tensor, edge_index=edge_index_62, y=y_tensor)
    
    # Create 10% Temporal Split for Fine Tuning (First ~1 month)
    df_62["date_dt"] = pd.to_datetime(df_62["date"])
    min_date = df_62["date_dt"].min()
    split_date = df_62["date_dt"].quantile(0.10) # first 10% of days
    
    import random
    random.seed(42)
    # Actually, structural tuning works best on a random 10% of nodes rather than a sharp temporal cut 
    # to maintain graph connectivity across the full dataset while simulating a sparse labeling pipeline.
    # Let's say SIEM analysts labeled a random 10% of nodes:
    num_nodes = len(df_62)
    indices = np.arange(num_nodes)
    np.random.shuffle(indices)
    train_idx = indices[:int(0.10 * num_nodes)]
    test_idx = indices[int(0.10 * num_nodes):]
    
    train_mask = torch.zeros(num_nodes, dtype=torch.bool)
    test_mask = torch.zeros(num_nodes, dtype=torch.bool)
    train_mask[train_idx] = True
    test_mask[test_idx] = True
    
    log(f"Fine-tuning nodes (10%): {train_mask.sum().item():,} (Malicious: {y_tensor[train_mask].sum().item()})")
    log(f"Evaluating  nodes (90%): {test_mask.sum().item():,} (Malicious: {y_tensor[test_mask].sum().item()})")
    
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    model = GCN(in_channels=len(FEATURES)).to(device)
    
    # Load collapsed Zero-Shot r4.2 weights
    model.load_state_dict(torch.load(MODEL_WT, map_location=device))
    data = data.to(device)
    
    optimizer = torch.optim.Adam(model.parameters(), lr=0.005)
    criterion = torch.nn.CrossEntropyLoss()
    
    # Fine-tune Training Loop (Very few epochs required for recovery)
    model.train()
    for exp in range(30):
        optimizer.zero_grad()
        out = model(data.x, data.edge_index)
        loss = criterion(out[train_mask], data.y[train_mask])
        loss.backward()
        optimizer.step()
        if exp % 10 == 0:
            preds = F.softmax(out[train_mask], dim=1)[:, 1].detach().cpu().numpy()
            train_auc = roc_auc_score(data.y[train_mask].cpu(), preds)
            log(f"   Fine-Tune Epoch {exp} | Loss: {loss.item():.4f} | Label-10% AUC: {train_auc:.4f}")

    # Evaluate Recovery on the 90% Unlabeled Test Set
    model.eval()
    with torch.no_grad():
        out = model(data.x, data.edge_index)
        probs = F.softmax(out, dim=1)[:, 1].cpu().numpy()
        
    df_test = df_62.iloc[test_idx].copy()
    df_test["recovered_score"] = probs[test_idx]
    
    ft_auc, ft_r100, ft_r400, tot_test_ins = calc_user_metrics(df_test, "recovered_score", "label")
    log(f"\nFine-Tuned GCN Test User ROC-AUC: {ft_auc:.4f}")
    log(f"Fine-Tuned Recall@100  : {ft_r100}/{tot_test_ins} ({(ft_r100/tot_test_ins)*100:.1f}%)")
    log(f"Fine-Tuned Recall@400  : {ft_r400}/{tot_test_ins} ({(ft_r400/tot_test_ins)*100:.1f}%)")

    # Plot Recovery Result
    states = ["Zero-Shot GCN", "IsoForest Unsup Fallback", "GCN (10% Fine-Tuned)"]
    aucs = [0.4804, iso_auc, ft_auc]
    colors = ['#D64933', '#F4B942', '#2E86AB']
    
    plt.style.use('seaborn-v0_8-darkgrid')
    fig, ax = plt.subplots(figsize=(8, 6))
    bars = ax.bar(states, aucs, color=colors, edgecolor='black', linewidth=1.5, width=0.5)
    
    for bar in bars:
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height+0.02,
                f'{height:.4f}', ha='center', va='bottom', fontweight='bold', fontsize=12)
        
    ax.axhline(0.5, color='gray', linestyle='--', linewidth=2, label='Random Baseline')
    ax.set_ylim(0, 1.1)
    ax.set_title("System Recovery Post-Drift on r6.2 Target Domain\n(User-Level ROC-AUC Comparison)", fontweight='bold', fontsize=14, pad=15)
    ax.set_ylabel("User-Level ROC-AUC", fontweight='bold')
    ax.legend(loc='upper right')
    plt.tight_layout()
    plt.savefig(os.path.join(FIG_DIR, 'adaptive_recovery_chart.png'), dpi=300)
    plt.close()
    
    log(f"\nSaved adaptive recovery comparison chart to 'adaptive_recovery_chart.png'")

if __name__ == "__main__":
    main()
