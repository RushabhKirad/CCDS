import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from scipy.stats import entropy
import sys

def log(msg): print(msg); sys.stdout.flush()

BASE_DIR   = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FIG_DIR    = os.path.join(BASE_DIR, "results", "figures")
METRIC_DIR = os.path.join(BASE_DIR, "results", "metrics")
R42_PATH = os.path.join(BASE_DIR, "data", "processed", "user_day_dataframe_r42.csv")
R62_PATH = os.path.join(BASE_DIR, "data", "processed", "user_day_dataframe_v62.csv")

FEATURES = [
    "logon_count", "after_hours_flag", "unique_pc_count",
    "usb_connect_count", "usb_disconnect_count", "usb_first_time_flag",
    "files_copied", "exe_copied_flag",
    "emails_sent", "external_email_ratio",
    "http_visit_count", "job_site_visits", "suspicious_url_visits"
]

def calculate_psi_and_kl(expected_array, actual_array, bins=10):
    """
    Computes Population Stability Index (PSI) and discrete KL Divergence.
    """
    # Define bins based on expected (r4.2)
    # Using quantiles to ensure bins are populated, but handling duplicate edges
    try:
        bin_edges = np.unique(np.percentile(expected_array, np.linspace(0, 100, bins + 1)))
        if len(bin_edges) < 2:
            # Fallback if too many zeros
            bin_edges = np.array([-np.inf, 0.5, np.inf])
    except:
        bin_edges = np.array([-np.inf, np.inf])
        
    bin_edges[0]  = -np.inf
    bin_edges[-1] = np.inf
    
    # Calculate percentages
    expected_counts, _ = np.histogram(expected_array, bins=bin_edges)
    actual_counts, _   = np.histogram(actual_array, bins=bin_edges)
    
    expected_pct = expected_counts / len(expected_array)
    actual_pct   = actual_counts / len(actual_array)
    
    # Avoid zero division
    expected_pct = np.clip(expected_pct, a_min=0.0001, a_max=None)
    actual_pct   = np.clip(actual_pct, a_min=0.0001, a_max=None)
    
    # Normalize back to 1
    expected_pct /= expected_pct.sum()
    actual_pct   /= actual_pct.sum()
    
    psi_values = (actual_pct - expected_pct) * np.log(actual_pct / expected_pct)
    psi = np.sum(psi_values)
    
    kl = entropy(actual_pct, expected_pct)
    return psi, kl

def main():
    log("1. Loading Data...")
    df_42 = pd.read_csv(R42_PATH)
    # Filter r4.2 to Train Data only
    df_42["date_dt"] = pd.to_datetime(df_42["date"])
    df_42_train = df_42[df_42["date_dt"] < pd.to_datetime("2010-09-30")]
    
    df_62 = pd.read_csv(R62_PATH)
    
    log(f"   r4.2 Train (Reference) : {len(df_42_train):,} rows")
    log(f"   r6.2 Total (Target)    : {len(df_62):,} rows")

    log("\n2. Computing Feature Drift (PSI & KL)...")
    drift_metrics = []
    
    for f in FEATURES:
        ref_data = df_42_train[f].values
        tgt_data = df_62[f].values
        
        psi, kl = calculate_psi_and_kl(ref_data, tgt_data, bins=10)
        drift_metrics.append({'Feature': f, 'PSI': psi, 'KL': kl})
        log(f"   {f:<25} | PSI: {psi:.4f} | KL: {kl:.4f}")

    drift_df = pd.DataFrame(drift_metrics).sort_values("PSI", ascending=False)
    
    # Aggregate Drift Score
    global_psi = drift_df["PSI"].mean()
    log(f"\n======================================")
    log(f"GLOBAL AGGREGATE DRIFT (Mean PSI): {global_psi:.4f}")
    if global_psi > 0.2:
        log(f"TRIGGER: Significant Drift Detected (> 0.2 threshold)")
    log(f"======================================")
    
    # --- Plotting 1: PSI Bar Chart ---
    plt.style.use('seaborn-v0_8-darkgrid')
    plt.figure(figsize=(10, 6))
    sns.barplot(x="PSI", y="Feature", data=drift_df, palette="Reds_r")
    plt.axvline(x=0.2, color='black', linestyle='--', label='Severe Drift Threshold (0.2)')
    plt.title(f'Population Stability Index (PSI) per Feature\nr4.2 vs r6.2 (Global PSI: {global_psi:.2f})', fontsize=14, fontweight='bold')
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(FIG_DIR, 'drift_psi_chart.png'), dpi=300)
    plt.close()
    
    # --- Plotting 2: KDE Overlays for Top 3 Drifting Features ---
    top_3_features = drift_df.head(3)['Feature'].tolist()
    log(f"\nGenerating Distribution Overlays for Top 3 Drifting Features: {top_3_features}")
    
    fig, axes = plt.subplots(1, 3, figsize=(18, 5))
    for i, f in enumerate(top_3_features):
        ax = axes[i]
        
        # Sampling 100k points to make KDE plotting fast and preventing memory issues
        np.random.seed(42)
        ref_sample = np.random.choice(df_42_train[f].values, min(100000, len(df_42_train)), replace=False)
        tgt_sample = np.random.choice(df_62[f].values, min(100000, len(df_62)), replace=False)
        
        # For long tails, we log transform (+1) for better visualization
        ref_log = np.log1p(ref_sample)
        tgt_log = np.log1p(tgt_sample)
        
        sns.kdeplot(ref_log, fill=True, color='#2E86AB', label='r4.2 (Source)', ax=ax, alpha=0.5)
        sns.kdeplot(tgt_log, fill=True, color='#D64933', label='r6.2 (Target)', ax=ax, alpha=0.5)
        
        ax.set_title(f'Drift in {f}\n(Log Scale)', fontweight='bold')
        ax.set_xlabel(f'log1p({f})')
        ax.set_ylabel('Density')
        if i == 0: ax.legend()
        
    plt.tight_layout()
    plt.savefig(os.path.join(FIG_DIR, 'drift_top3_distributions.png'), dpi=300)
    plt.close()

if __name__ == "__main__":
    main()
