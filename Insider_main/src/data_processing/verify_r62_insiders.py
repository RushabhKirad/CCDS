# -*- coding: utf-8 -*-
"""
Verify exact malicious session counts per r6.2 insider.
Run:  python verify_r62_insiders.py
"""
import pandas as pd, os, sys
from collections import defaultdict

def log(m): print(m); sys.stdout.flush()

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ANS  = os.path.join(PROJECT_ROOT, "data", "raw", "datasets", "answers")
R62  = os.path.join(PROJECT_ROOT, "data", "raw", "datasets", "r6.2")

# ── 1. Load insider windows ───────────────────────────────────────────────────
ins = pd.read_csv(os.path.join(ANS, "insiders.csv"))
r62 = ins[ins["dataset"].astype(str).str.strip() == "6.2"].copy()

# CDE1846 has a malformed start date '/21/2011' in insiders.csv -- patch it
r62["start_raw"] = r62["start"].astype(str)
r62["start_raw"] = r62["start_raw"].str.replace(r"^/", "01/", regex=True)
r62["start"] = pd.to_datetime(r62["start_raw"], errors="coerce")
r62["end"]   = pd.to_datetime(r62["end"],       errors="coerce")
r62["window_days"] = (r62["end"] - r62["start"]).dt.days + 1

log("=" * 65)
log("  r6.2 INSIDER WINDOWS (insiders.csv)")
log("=" * 65)
log("{:<12} {:>3}  {:<12} {:<12} {:>9}".format(
    "user", "sc", "start", "end", "win_days"))
for _, row in r62.iterrows():
    log("{:<12} {:>3}  {:<12} {:<12} {:>9}".format(
        row["user"], int(row["scenario"]),
        str(row["start"])[:10], str(row["end"])[:10],
        int(row["window_days"])))

# ── 2. Parse event logs from r6.2-N.csv answer files ─────────────────────────
log("")
log("=" * 65)
log("  ANSWER FILE ANALYSIS (malicious events only)")
log("=" * 65)

total_event_days = 0
for sc in range(1, 6):
    fname = "r6.2-{}.csv".format(sc)
    fpath = os.path.join(ANS, fname)
    if not os.path.exists(fpath):
        log("  {} : NOT FOUND".format(fname)); continue

    lines = [l.strip() for l in
             open(fpath, "r", errors="replace").read().splitlines() if l.strip()]
    users, dates, etypes = set(), set(), defaultdict(int)
    for line in lines:
        parts = line.split(",")
        if len(parts) < 4: continue
        etype    = parts[0].strip().strip('"')
        date_str = parts[2].strip().strip('"')
        user     = parts[3].strip().strip('"')
        try:
            dt = pd.to_datetime(date_str, dayfirst=False, errors="coerce")
            if pd.notna(dt):
                dates.add(dt.date()); users.add(user); etypes[etype] += 1
        except Exception:
            pass

    total_event_days += len(dates)
    log("Scenario {:d}  ({})".format(sc, fname))
    log("  User(s)      : {}".format(users))
    log("  Total events : {:,}".format(len(lines)))
    log("  Unique dates : {}  (malicious-event days in answer log)".format(len(dates)))
    dr = "{} --> {}".format(min(dates), max(dates)) if dates else "N/A"
    log("  Date range   : {}".format(dr))
    log("  Event types  : {}".format(dict(etypes)))
    log("")

# ── 3. Ground-truth session count from logon.csv ─────────────────────────────
log("=" * 65)
log("  SESSION-DAYS FROM logon.csv  (actual logon activity in window)")
log("=" * 65)
log("Reading r6.2/logon.csv in chunks ...")

inside_users = {
    row["user"]: (row["start"], row["end"])
    for _, row in r62.iterrows()
}
session_sets = defaultdict(set)

for chunk in pd.read_csv(
        os.path.join(R62, "logon.csv"),
        usecols=["date", "user"],
        parse_dates=["date"],
        chunksize=300_000):
    for user, (start, end) in inside_users.items():
        mask = ((chunk["user"] == user) &
                (chunk["date"] >= start) &
                (chunk["date"] <= end))
        hits = chunk.loc[mask, "date"].dt.date.unique()
        session_sets[user].update(hits)

log("")
log("{:<12} {:>3}  {:<12} {:<12} {:>9}".format(
    "user", "sc", "start_date", "end_date", "sess_days"))
total_malicious = 0
for _, row in r62.iterrows():
    u   = row["user"]
    sc  = int(row["scenario"])
    cnt = len(session_sets[u])
    total_malicious += cnt
    log("{:<12} {:>3}  {:<12} {:<12} {:>9}".format(
        u, sc,
        str(row["start"])[:10], str(row["end"])[:10],
        cnt))

log("")
log("=" * 65)
log("  SUMMARY")
log("=" * 65)
log("Total malicious session-days (ground truth) : {}".format(total_malicious))
log("r6.2 approx total sessions (4k users x 1yr) : {:,}".format(4000 * 365))
log("Session-level positive rate (approx)         : {:.5f}%".format(
    total_malicious / (4000 * 365) * 100))
log("If session-level ROC at random = 0.50, watch for inflation.")
log("")
log("Evaluation recommendation:")
log("  - User-level ranking (max anomaly score per user)")
log("  - Recall@5 : are all 5 insiders in top-5 flagged users?")
log("  - Recall@10: all 5 in top-10?")
log("  - User-level ROC-AUC (binary: insider vs non-insider, 1 score/user)")
log("ALL DONE.")
