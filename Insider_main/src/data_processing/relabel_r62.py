# -*- coding: utf-8 -*-
"""
Update user_day_dataframe_v62.csv labels with all 29 malicious users.
Reads exact dates from both insiders.csv and r6.2-N.csv answer files to construct full malicious windows per user.
"""
import pandas as pd
import os
import sys
from collections import defaultdict

def log(msg): print(msg); sys.stdout.flush()

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ANS_DIR  = os.path.join(PROJECT_ROOT, "data", "raw", "datasets", "answers")
DF_PATH  = os.path.join(PROJECT_ROOT, "data", "processed", "user_day_dataframe_v62.csv")

log("1. Parsing exact malicious windows from answers...")
user_windows = defaultdict(list)

# Fallback: insiders.csv primary users
ins = pd.read_csv(os.path.join(ANS_DIR, "insiders.csv"))
r62_ins = ins[ins["dataset"].astype(str).str.strip() == "6.2"].copy()
r62_ins["start_raw"] = r62_ins["start"].astype(str).str.replace(r"^/", "01/", regex=True)
r62_ins["start"] = pd.to_datetime(r62_ins["start_raw"], errors="coerce")
r62_ins["end"]   = pd.to_datetime(r62_ins["end"], errors="coerce")
for _, row in r62_ins.iterrows():
    if pd.notna(row["start"]) and pd.notna(row["end"]):
        user_windows[row["user"].strip()].append((row["start"].date(), row["end"].date()))

# Primary exact dates from event answer files
for sc in range(1, 6):
    fpath = os.path.join(ANS_DIR, f"r6.2-{sc}.csv")
    if not os.path.exists(fpath): continue
    lines = [l.strip() for l in open(fpath, "r", errors="replace").read().splitlines() if l.strip()]
    dates_by_user = defaultdict(list)
    for line in lines:
        parts = line.split(",")
        if len(parts) < 4: continue
        date_str = parts[2].strip().strip('"')
        user     = parts[3].strip().strip('"')
        try:
            dt = pd.to_datetime(date_str, dayfirst=False, errors="coerce")
            if pd.notna(dt):
                dates_by_user[user].append(dt.date())
        except:
            pass
    for u, dates in dates_by_user.items():
        if dates:
            user_windows[u].append((min(dates), max(dates)))

final_windows = {}
log("\nFound Malicious Users:")
for u, windows in user_windows.items():
    if not windows: continue
    start = min(w[0] for w in windows)
    end = max(w[1] for w in windows)
    final_windows[u] = (start, end)
    log(f"  {u}: {start} to {end}")

log(f"\nTotal Malicious Users Identified: {len(final_windows)}")

log("\n2. Applying labels to user_day_dataframe_v62.csv...")
df = pd.read_csv(DF_PATH)
df["date_dt"] = pd.to_datetime(df["date"]).dt.date
df["label"] = 0

for u, (start, end) in final_windows.items():
    mask = (df['user'] == u) & (df['date_dt'] >= start) & (df['date_dt'] <= end)
    df.loc[mask, 'label'] = 1

df = df.drop(columns=["date_dt"])

mal_count = df['label'].sum()
log(f"New Malicious Sessions Count: {mal_count}")
log(f"Prevalence Update: {mal_count / len(df):.6f}")

df.to_csv(DF_PATH, index=False)
log("Re-labeled data saved successfully.")
