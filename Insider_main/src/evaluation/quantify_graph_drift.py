import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FIG_DIR  = os.path.join(BASE_DIR, "results", "figures")
R42_PATH = os.path.join(BASE_DIR, "data", "processed", "user_day_dataframe_r42.csv")
R62_PATH = os.path.join(BASE_DIR, "data", "processed", "user_day_dataframe_v62.csv")

def extract_graph_metrics(df, dataset_name):
    # Group by user to find chain lengths (number of chronological session nodes per user)
    # The edges in our GCN are strictly linear sequential edges within a user's temporal chain.
    user_counts = df.groupby("user").size()
    
    # 1. Chain Lengths -> Number of nodes in a connected component
    chain_lengths = user_counts.values
    avg_chain = np.mean(chain_lengths)
    med_chain = np.median(chain_lengths)
    max_chain = np.max(chain_lengths)
    
    # 2. Node Degrees
    # In a chronological chain x1 - x2 - x3 - x4:
    # Degree of endpoints = 1. Degree of internal nodes = 2.
    # Total nodes = N. Total edges = N - C (where C = number of users/chains)
    # Average degree = 2 * Edges / Nodes = 2 * (N - C) / N
    N = len(df)
    C = len(user_counts)
    avg_degree = 2 * (N - C) / N
    
    # 3. Density
    # Max possible edges connecting anyone to anyone = N*(N-1)/2
    density = (N - C) / (N * (N - 1) / 2) if N > 1 else 0
    
    # Fragmentation metric: what % of users have very short chains (< 10 days)
    fragmented_pct = np.sum(chain_lengths < 10) / C * 100
    
    return {
        "Dataset": dataset_name,
        "Total Nodes": N,
        "Total Users (Components)": C,
        "Avg Chain Length": avg_chain,
        "Median Chain Length": med_chain,
        "Max Chain Length": max_chain,
        "Avg Node Degree": avg_degree,
        "Fragmented Users (<10 sessions)": fragmented_pct,
        "Chain Lengths Dist": chain_lengths
    }

def main():
    print("Loading Graph Data...")
    df_42 = pd.read_csv(R42_PATH)
    df_62 = pd.read_csv(R62_PATH)
    
    m_42 = extract_graph_metrics(df_42, "r4.2 (Train)")
    m_62 = extract_graph_metrics(df_62, "r6.2 (Target)")
    
    print("\n--- Structural Graph Drift Summary ---")
    keys = ["Total Nodes", "Total Users (Components)", "Avg Chain Length", "Median Chain Length", "Max Chain Length", "Avg Node Degree", "Fragmented Users (<10 sessions)"]
    print(f"{'Metric':<35} | {'r4.2 (Train)':<15} | {'r6.2 (Target)':<15}")
    print("-" * 75)
    for k in keys:
        v42 = m_42[k]
        v62 = m_62[k]
        if isinstance(v42, float):
            print(f"{k:<35} | {v42:<15.4f} | {v62:<15.4f}")
        else:
            print(f"{k:<35} | {v42:<15} | {v62:<15}")

    # Plot Chain Length Distributions
    plt.style.use('seaborn-v0_8-darkgrid')
    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    
    sns.histplot(m_42["Chain Lengths Dist"], bins=50, color='#2E86AB', ax=axes[0], kde=True)
    axes[0].set_title(f'r4.2 Session Chain Lengths\n(Mean: {m_42["Avg Chain Length"]:.1f} days/user)', fontweight='bold')
    axes[0].set_xlabel('Active Session Days')
    axes[0].set_ylabel('Number of Users')
    
    sns.histplot(m_62["Chain Lengths Dist"], bins=50, color='#D64933', ax=axes[1], kde=True)
    axes[1].set_title(f'r6.2 Session Chain Lengths\n(Mean: {m_62["Avg Chain Length"]:.1f} days/user)', fontweight='bold')
    axes[1].set_xlabel('Active Session Days')
    axes[1].set_ylabel('Number of Users')
    
    plt.suptitle("Graph Structural Drift: Fragmentation of Temporal Chains", fontsize=16, fontweight='bold', y=1.02)
    plt.tight_layout()
    plt.savefig(os.path.join(FIG_DIR, 'drift_structural_chains.png'), dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"\nSaved graph structural drift visualization to 'drift_structural_chains.png'")

if __name__ == "__main__":
    main()
