import matplotlib.pyplot as plt
import numpy as np
import os
import matplotlib

# Set styling
plt.style.use('seaborn-v0_8-darkgrid')
matplotlib.rcParams.update({'font.size': 12, 'font.family': 'sans-serif'})

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── 1. ROC-AUC Collapse Bar Chart
fig, ax = plt.subplots(figsize=(8, 6))

datasets = ['CERT r4.2 (Train Domain)', 'CERT r6.2 (Zero-Shot)']
auc_scores = [0.9831, 0.4804]  # User-level ROC values
colors = ['#2E86AB', '#D64933']

bars = ax.bar(datasets, auc_scores, color=colors, width=0.5, edgecolor='black', linewidth=1.5)

# Add value labels
for bar in bars:
    height = bar.get_height()
    ax.text(bar.get_x() + bar.get_width() / 2., height - 0.05,
            f'{height:.4f}', ha='center', va='bottom', color='white', fontweight='bold', fontsize=14)

# Draw random baseline
ax.axhline(0.5, color='gray', linestyle='--', linewidth=2, label='Random Baseline (0.50)')
ax.text(-0.4, 0.52, 'Random Guessing', color='gray', fontsize=10, fontweight='bold')

ax.set_ylim(0, 1.1)
ax.set_ylabel('User-Level ROC-AUC', fontweight='bold', fontsize=13)
ax.set_title('Supervised Graph Model Generalization Collapse\n(Cross-Domain: Data Exfiltration $\\rightarrow$ IT Sabotage)', 
             fontweight='bold', fontsize=14, pad=15)
ax.grid(axis='y', linestyle='--', alpha=0.7)
ax.legend(loc='upper right')

plt.tight_layout()
collapse_path = os.path.join(PROJECT_ROOT, "results", "figures", "zero_shot_roc_collapse.png")
plt.savefig(collapse_path, dpi=300, bbox_inches='tight')
plt.close()

# ── 2. User Rank Histogram (r6.2 Zero-Shot)
# Mocking the curve based on the real ranks: [1, 101, 148, 248, 334, 478, 576, 597, 754, 761, 777, ...]
real_ranks = [1, 101, 148, 248, 334, 478, 576, 597, 754, 761, 777, 1031, 1317, 1651, 2048, 2078, 2423, 2994, 3163, 3656, 3734, 3762, 3867, 3918, 3925, 3973, 3979, 3985, 3991]

fig, ax = plt.subplots(figsize=(10, 5))

# Plot histogram of where the 29 insiders landed in the rank order of 4000 users
n, bins, patches = ax.hist(real_ranks, bins=40, range=(1, 4000), color='#D64933', edgecolor='black', alpha=0.8)

ax.set_xlabel('Anomaly Score Rank (1 = Most Anomalous)', fontweight='bold', fontsize=12)
ax.set_ylabel('Number of Malicious Users', fontweight='bold', fontsize=12)
ax.set_title('Distribution of Insider Ranks in CERT r6.2 Zero-Shot Evaluation (Total Users: 4,000)', fontweight='bold', fontsize=14, pad=15)

# Annotate the Rank 1 Hit
ax.annotate('Top Anomaly (Rank 1) is a True Insider', 
            xy=(1, 1), xytext=(300, 3),
            arrowprops=dict(facecolor='black', shrink=0.05, width=2, headwidth=8),
            fontsize=12, fontweight='bold', color='#2E86AB')

# Add "Random Distribution" line expectation (29 users / 40 bins = ~0.725 per bin)
ax.axhline(29/40, color='gray', linestyle='--', linewidth=2, label='Expected Uniform Distribution (Random)')

ax.set_xlim(0, 4000)
ax.legend(loc='upper right')

plt.tight_layout()
hist_path = os.path.join(PROJECT_ROOT, "results", "figures", "zero_shot_rank_hist.png")
plt.savefig(hist_path, dpi=300, bbox_inches='tight')
plt.close()

print(f"Saved: {collapse_path}")
print(f"Saved: {hist_path}")
