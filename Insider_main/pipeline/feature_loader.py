import os
import pandas as pd
import numpy as np

try:
    from sklearn.preprocessing import StandardScaler
except ImportError:
    class StandardScaler:
        def __init__(self):
            self.mean_ = None
            self.scale_ = None
        def fit(self, X):
            self.mean_ = np.mean(X, axis=0)
            self.scale_ = np.std(X, axis=0)
            self.scale_[self.scale_ == 0] = 1.0
            return self
        def transform(self, X):
            return (X - self.mean_) / self.scale_
        def fit_transform(self, X):
            return self.fit(X).transform(X)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R42_PATH = os.path.join(BASE_DIR, "data", "processed", "user_day_dataframe_r42.csv")
R62_PATH = os.path.join(BASE_DIR, "data", "processed", "user_day_dataframe_v62.csv")

FEATURES = [
    "logon_count", "after_hours_flag", "unique_pc_count",
    "usb_connect_count", "usb_disconnect_count", "usb_first_time_flag",
    "files_copied", "exe_copied_flag",
    "emails_sent", "external_email_ratio",
    "http_visit_count", "job_site_visits", "suspicious_url_visits"
]

# ── Module-level cache: load each dataset once per server lifetime ─────────────
_cache: dict = {}

def _load_r42_raw():
    """Load and parse r4.2 CSV once, cache it."""
    if "r42_raw" not in _cache:
        df = pd.read_csv(R42_PATH)
        df["date_dt"] = pd.to_datetime(df["date"])
        _cache["r42_raw"] = df
    return _cache["r42_raw"]

def load_dataset(dataset_name: str):
    if dataset_name == "r42_train":
        df = _load_r42_raw()
        df = df[df["date_dt"] < pd.to_datetime("2010-09-30")].reset_index(drop=True)
    elif dataset_name == "r42_test":
        df = _load_r42_raw()
        df = df[df["date_dt"] >= pd.to_datetime("2010-09-30")].reset_index(drop=True)
    elif dataset_name == "r62":
        if "r62" not in _cache:
            _cache["r62"] = pd.read_csv(R62_PATH)
        df = _cache["r62"]
    else:
        raise ValueError("Invalid dataset.")

    key = f"scaled_{dataset_name}"
    if key not in _cache:
        scaler = StandardScaler()
        _cache[key] = scaler.fit_transform(df[FEATURES].values)
    x_scaled = _cache[key]

    return df, x_scaled

def get_r42_train_df():
    """Returns r4.2 train split (used for PSI baseline). Cached."""
    if "r42_train_df" not in _cache:
        df = _load_r42_raw()
        _cache["r42_train_df"] = df[df["date_dt"] < pd.to_datetime("2010-09-30")]
    return _cache["r42_train_df"]
