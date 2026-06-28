# -*- coding: utf-8 -*-
"""
Generate user_day_dataframe for CERT r6.2
Extracts the EXACT 13 features used in r4.2 for zero-shot generalization testing.
"""
import pandas as pd
import numpy as np
import os
import sys
from collections import defaultdict
from urllib.parse import urlparse

def log(msg):
    print(msg)
    sys.stdout.flush()

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
R62_DIR  = os.path.join(PROJECT_ROOT, "data", "raw", "datasets", "r6.2")
ANS_DIR  = os.path.join(PROJECT_ROOT, "data", "raw", "datasets", "answers")
OUT_FILE = os.path.join(PROJECT_ROOT, "data", "processed", "user_day_dataframe_v62.csv")

# =============================================================================
# 1. LOAD INSIDER GROUND TRUTH (r6.2 scenario windows)
# =============================================================================
log("[1/6] Loading insider ground truth...")
ins = pd.read_csv(os.path.join(ANS_DIR, "insiders.csv"))
r62_ins = ins[ins["dataset"].astype(str).str.strip() == "6.2"].copy()

# Fix malformed start date for CDE1846 ('/21/2011' -> '01/21/2011')
r62_ins["start_raw"] = r62_ins["start"].astype(str)
r62_ins["start_raw"] = r62_ins["start_raw"].str.replace(r"^/", "01/", regex=True)
r62_ins["start"] = pd.to_datetime(r62_ins["start_raw"], errors="coerce")
r62_ins["end"]   = pd.to_datetime(r62_ins["end"],       errors="coerce")

# Build a dictionary for fast lookup: insider_windows[user] = list of (start, end)
insider_windows = defaultdict(list)
for _, row in r62_ins.iterrows():
    insider_windows[row["user"]].append((row["start"], row["end"]))

def is_malicious(user, date):
    if user not in insider_windows:
        return 0
    dt_date = pd.to_datetime(date).date()
    for start, end in insider_windows[user]:
        if pd.isna(start) or pd.isna(end): continue
        if start.date() <= dt_date <= end.date():
            return 1
    return 0

# =============================================================================
# 2. LOGON.CSV: logon_count, after_hours_flag, unique_pc_count
# =============================================================================
log("[2/6] Processing logon.csv...")
session_dict = defaultdict(lambda: {
    "logon_count": 0,
    "after_hours_flag": 0,
    "unique_pcs": set(),
    "usb_connect_count": 0,
    "usb_disconnect_count": 0,
    "files_copied": 0,
    "exe_copied_flag": 0,
    "emails_sent": 0,
    "external_emails": 0,
    "job_site_visits": 0,
    "suspicious_url_visits": 0,
    "http_visit_count": 0
})

chunk_size = 5_000_000
for chunk in pd.read_csv(os.path.join(R62_DIR, "logon.csv"), usecols=["date", "user", "pc", "activity"], chunksize=chunk_size):
    chunk["date_dt"] = pd.to_datetime(chunk["date"], errors="coerce")
    chunk = chunk.dropna(subset=["date_dt"])
    chunk["day"] = chunk["date_dt"].dt.date
    chunk["hour"] = chunk["date_dt"].dt.hour
    
    for _, row in chunk.iterrows():
        key = (row["user"], row["day"])
        sess = session_dict[key]
        
        if row["activity"] == "Logon":
            sess["logon_count"] += 1
            if row["hour"] < 7 or row["hour"] >= 18:
                sess["after_hours_flag"] = 1
        
        sess["unique_pcs"].add(row["pc"])

log(f"      Found {len(session_dict):,} primitive sessions from logons.")

# =============================================================================
# 3. DEVICE.CSV: usb_connect_count, usb_disconnect_count
# =============================================================================
log("[3/6] Processing device.csv...")
user_first_usb_date = {}

for chunk in pd.read_csv(os.path.join(R62_DIR, "device.csv"), usecols=["date", "user", "activity"], chunksize=chunk_size):
    chunk["date_dt"] = pd.to_datetime(chunk["date"], errors="coerce")
    chunk = chunk.dropna(subset=["date_dt"])
    chunk["day"] = chunk["date_dt"].dt.date
    
    for _, row in chunk.iterrows():
        u = row["user"]
        day = row["day"]
        key = (u, day)
        sess = session_dict[key]
        
        if row["activity"] == "Connect":
            sess["usb_connect_count"] += 1
            if u not in user_first_usb_date or day < user_first_usb_date[u]:
                user_first_usb_date[u] = day
        elif row["activity"] == "Disconnect":
            sess["usb_disconnect_count"] += 1

# =============================================================================
# 4. FILE.CSV: files_copied, exe_copied_flag
# =============================================================================
log("[4/6] Processing file.csv...")
# file.csv in r6.2 uses "copy" as lowercase or titlecase activity
for chunk in pd.read_csv(os.path.join(R62_DIR, "file.csv"), usecols=["date", "user", "filename", "activity"], chunksize=chunk_size):
    chunk["date_dt"] = pd.to_datetime(chunk["date"], errors="coerce")
    chunk = chunk.dropna(subset=["date_dt"])
    chunk["day"] = chunk["date_dt"].dt.date
    
    for _, row in chunk.iterrows():
        key = (row["user"], row["day"])
        sess = session_dict[key]
        
        # In r4.2 activity was always copy, r6.2 has open, write, copy, delete
        if str(row["activity"]).lower().strip() == "copy":
            sess["files_copied"] += 1
            fname = str(row["filename"]).lower()
            if fname.endswith(".exe"):
                sess["exe_copied_flag"] = 1

# =============================================================================
# 5. EMAIL.CSV: emails_sent, external_emails
# =============================================================================
log("[5/6] Processing email.csv (chunked)...")
# email.csv is ~8GB in r6.2, chunking required
for chunk in pd.read_csv(os.path.join(R62_DIR, "email.csv"), usecols=["date", "user", "to", "activity"], chunksize=chunk_size):
    chunk["date_dt"] = pd.to_datetime(chunk["date"], errors="coerce")
    chunk = chunk.dropna(subset=["date_dt"])
    chunk["day"] = chunk["date_dt"].dt.date
    
    for _, row in chunk.iterrows():
        key = (row["user"], row["day"])
        sess = session_dict[key]
        
        # r6.2 replaces 'receipt' with 'View', so we only count Send
        if str(row["activity"]).lower().strip() == "send":
            sess["emails_sent"] += 1
            to_addrs = str(row["to"]).split(";")
            is_external = any("dtaa.com" not in addr.lower() for addr in to_addrs if addr.strip())
            if is_external:
                sess["external_emails"] += 1

# =============================================================================
# 6. HTTP.CSV: http_visit_count, job_site_visits, suspicious_url_visits
# =============================================================================
log("[6/6] Processing http.csv (chunked, 90GB) ...")
# This will take a while, 90GB file. Chunksize 10M is safe for memory usually.
job_domains = {"monster.com", "careerbuilder.com", "linkedin.com", "simplyhired.com", "indeed.com", "jobhuntersbible.com", "craigslist.org", "yahoo.com/hotjobs"}
suspicious_keywords = ["wikileaks", "keylogger", "hacking", "darknet", "dropbox", "mega.nz", "rapidshare"]

rows_processed = 0
for chunk in pd.read_csv(os.path.join(R62_DIR, "http.csv"), usecols=["date", "user", "url", "activity"], chunksize=chunk_size):
    chunk["date_dt"] = pd.to_datetime(chunk["date"], errors="coerce")
    chunk = chunk.dropna(subset=["date_dt"])
    chunk["day"] = chunk["date_dt"].dt.date
    rows_processed += len(chunk)
    
    for _, row in chunk.iterrows():
        # r6.2 has "WWW Download", "WWW Upload", "WWW Visit"
        # We count all as visits to match r4.2 generalized volume, or just "WWW Visit"?
        # Base paper and r4.2 just had domains, so we count all http requests.
        key = (row["user"], row["day"])
        sess = session_dict[key]
        
        sess["http_visit_count"] += 1
        
        url = str(row["url"]).lower()
        if any(job_domain in url for job_domain in job_domains):
            sess["job_site_visits"] += 1
        
        if any(sus in url for sus in suspicious_keywords):
            sess["suspicious_url_visits"] += 1
            
    if rows_processed % 30_000_000 == 0:
        log(f"      ...processed {rows_processed:,} http rows...")

# =============================================================================
# 7. ASSEMBLE DATAFRAME
# =============================================================================
log("[7/7] Assembling final user-day dataframe...")

data = []
for (u, day), metrics in session_dict.items():
    # Finalize derived metrics
    unique_pc_count = len(metrics["unique_pcs"])
    external_email_ratio = metrics["external_emails"] / metrics["emails_sent"] if metrics["emails_sent"] > 0 else 0.0
    
    usb_first_time_flag = 1 if (u in user_first_usb_date and user_first_usb_date[u] == day) else 0
    label = is_malicious(u, day)
    
    data.append({
        "user": u,
        "date": day.strftime("%Y-%m-%d"),
        "logon_count": metrics["logon_count"],
        "after_hours_flag": metrics["after_hours_flag"],
        "unique_pc_count": unique_pc_count,
        "usb_connect_count": metrics["usb_connect_count"],
        "usb_disconnect_count": metrics["usb_disconnect_count"],
        "usb_first_time_flag": usb_first_time_flag,
        "files_copied": metrics["files_copied"],
        "exe_copied_flag": metrics["exe_copied_flag"],
        "emails_sent": metrics["emails_sent"],
        "external_email_ratio": round(external_email_ratio, 4),
        "job_site_visits": metrics["job_site_visits"],
        "suspicious_url_visits": metrics["suspicious_url_visits"],
        "http_visit_count": metrics["http_visit_count"],
        "label": label
    })

df = pd.DataFrame(data)
df = df.sort_values(["user", "date"]).reset_index(drop=True)

df.to_csv(OUT_FILE, index=False)
log("=" * 65)
log(f"SAVED: {OUT_FILE}")
log(f"Total Rows (Sessions): {len(df):,}")
malicious_count = df["label"].sum()
log(f"Malicious Sessions:   {malicious_count:,}")
log(f"Label Mean:           {malicious_count / len(df):.6f}")
log("=" * 65)
