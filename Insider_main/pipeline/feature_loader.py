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
            # Prevent division by zero
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

def load_dataset(dataset_name: str):
    """
    Loads raw dataframe and returns it along with raw features and a standard scaler.
    """
    if dataset_name == "r42_train":
        df = pd.read_csv(R42_PATH)
        df["date_dt"] = pd.to_datetime(df["date"])
        df = df[df["date_dt"] < pd.to_datetime("2010-09-30")].reset_index(drop=True)
    elif dataset_name == "r42_test":
        df = pd.read_csv(R42_PATH)
        df["date_dt"] = pd.to_datetime(df["date"])
        df = df[df["date_dt"] >= pd.to_datetime("2010-09-30")].reset_index(drop=True)
    elif dataset_name == "r62":
        df = pd.read_csv(R62_PATH)
    else:
        raise ValueError("Invalid dataset.")
        
    scaler = StandardScaler()
    x_scaled = scaler.fit_transform(df[FEATURES].values)
    
    return df, x_scaled
    
def get_r42_train_df():
    # Helper to get the baseline reference data used for PSI
    df = pd.read_csv(R42_PATH)
    df["date_dt"] = pd.to_datetime(df["date"])
    # Return chronologically split train subset
    return df[df["date_dt"] < pd.to_datetime("2010-09-30")]
