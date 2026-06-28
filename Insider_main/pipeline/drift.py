import numpy as np
import pandas as pd
from pipeline.feature_loader import get_r42_train_df, FEATURES

def calculate_psi(expected_array, actual_array, bins=10):
    try:
        bin_edges = np.unique(np.percentile(expected_array, np.linspace(0, 100, bins + 1)))
        if len(bin_edges) < 2:
            bin_edges = np.array([-np.inf, 0.5, np.inf])
    except:
        bin_edges = np.array([-np.inf, np.inf])
        
    bin_edges[0]  = -np.inf
    bin_edges[-1] = np.inf
    
    expected_counts, _ = np.histogram(expected_array, bins=bin_edges)
    actual_counts, _   = np.histogram(actual_array, bins=bin_edges)
    
    expected_pct = expected_counts / len(expected_array)
    actual_pct   = actual_counts / len(actual_array)
    
    expected_pct = np.clip(expected_pct, a_min=0.0001, a_max=None)
    actual_pct   = np.clip(actual_pct, a_min=0.0001, a_max=None)
    
    expected_pct /= expected_pct.sum()
    actual_pct   /= actual_pct.sum()
    
    psi_values = (actual_pct - expected_pct) * np.log(actual_pct / expected_pct)
    return np.sum(psi_values)

def compute_dataset_drift(target_df):
    """
    Computes drift of target_df against the r4.2 train baseline.
    Returns global_psi, psi_per_feature, and top drifting features.
    """
    ref_df = get_r42_train_df()
    
    psi_dict = {}
    for f in FEATURES:
        # Optimization: use small uniform samples if target data is massive
        # For demo purposes, we compute exact PSI 
        psi = calculate_psi(ref_df[f].values, target_df[f].values)
        psi_dict[f] = psi

    global_psi = float(np.mean(list(psi_dict.values())))
    
    # Sort features by highest drift
    sorted_features = sorted(psi_dict.keys(), key=lambda k: psi_dict[k], reverse=True)
    top_drifting = sorted_features[:3]
    
    return {
        "global_psi": global_psi,
        "psi_per_feature": psi_dict,
        "top_drifting_features": top_drifting
    }
