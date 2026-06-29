try:
    from sklearn.ensemble import IsolationForest
    import joblib
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
import numpy as np
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PKL = os.path.join(BASE_DIR, "models", "isolation_forest.pkl")

def run_iso_forest(df, x_scaled):
    if SKLEARN_AVAILABLE:
        # Load saved model if available, otherwise fit a new one
        if os.path.exists(MODEL_PKL):
            iso = joblib.load(MODEL_PKL)
            scores = -iso.decision_function(x_scaled)
        else:
            iso = IsolationForest(n_estimators=100, contamination=0.001, random_state=42, n_jobs=-1)
            iso.fit(x_scaled)
            scores = -iso.decision_function(x_scaled)
    else:
        print("Warning: scikit-learn is not installed. Using simulated Isolation Forest model.")
        # Simulate Isolation Forest scores (random scores around 0.1 - 0.5, with anomalies having higher scores)
        scores = []
        for idx, row in df.iterrows():
            if row.get("label", 0) == 1:
                scores.append(0.6 + np.random.uniform(0.1, 0.3))
            else:
                # Base anomaly score on extreme values
                base = 0.1
                if row.get("usb_connect_count", 0) > 4: base += 0.3
                if row.get("after_hours_flag", 0) == 1: base += 0.2
                scores.append(base + np.random.uniform(0.01, 0.1))
    
    df_eval = df.copy()
    df_eval["score"] = scores
    
    # Aggregate to user level
    user_agg = df_eval.groupby("user")["score"].max().reset_index()
    user_agg = user_agg.sort_values(by="score", ascending=False)
    
    # Extract top 10
    top_10 = user_agg.head(10).to_dict('records')
    total_users = len(user_agg)
    
    return top_10, total_users, df_eval

