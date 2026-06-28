# CERT r4.2 - Official Ground Truth Malicious Users
# Source: answers/insiders.csv (official CERT answer key)
# Scenario 1 = AB-I  (Data Exfiltration via wikileaks)
# Scenario 2 = AB-II (Job hunting + pre-departure USB theft)
# Scenario 3 = AB-III (ITAdmin sabotage via keylogger)

MALICIOUS_USERS = {
    "AAF0535": {"scenario": "AB-II", "start": "2010-06-28", "end": "2010-08-20"},
    "AAM0658": {"scenario": "AB-I", "start": "2010-10-23", "end": "2010-10-29"},
    "ABC0174": {"scenario": "AB-II", "start": "2010-10-27", "end": "2010-12-24"},
    "AJR0932": {"scenario": "AB-I", "start": "2010-09-10", "end": "2010-09-18"},
    "AKR0057": {"scenario": "AB-II", "start": "2010-10-04", "end": "2010-11-29"},
    "BBS0039": {"scenario": "AB-III", "start": "2010-08-12", "end": "2010-08-13"},
    "BDV0168": {"scenario": "AB-I", "start": "2010-07-30", "end": "2010-08-10"},
    "BIH0745": {"scenario": "AB-I", "start": "2010-07-13", "end": "2010-07-13"},
    "BLS0678": {"scenario": "AB-I", "start": "2010-09-21", "end": "2010-09-30"},
    "BSS0369": {"scenario": "AB-III", "start": "2010-09-30", "end": "2010-10-01"},
    "BTL0226": {"scenario": "AB-I", "start": "2010-10-06", "end": "2010-10-14"},
    "CAH0936": {"scenario": "AB-I", "start": "2010-08-11", "end": "2010-08-12"},
    "CCA0046": {"scenario": "AB-III", "start": "2010-10-14", "end": "2010-10-15"},
    "CCL0068": {"scenario": "AB-II", "start": "2010-12-27", "end": "2011-02-21"},
    "CEJ0109": {"scenario": "AB-II", "start": "2011-02-07", "end": "2011-04-01"},
    "CQW0652": {"scenario": "AB-II", "start": "2011-02-18", "end": "2011-04-14"},
    "CSC0217": {"scenario": "AB-III", "start": "2010-06-10", "end": "2010-06-11"},
    "DCH0843": {"scenario": "AB-I", "start": "2011-02-04", "end": "2011-02-04"},
    "DIB0285": {"scenario": "AB-II", "start": "2010-07-26", "end": "2010-09-13"},
    "DRR0162": {"scenario": "AB-II", "start": "2010-11-11", "end": "2011-01-04"},
    "EDB0714": {"scenario": "AB-II", "start": "2010-10-18", "end": "2010-12-14"},
    "EGD0132": {"scenario": "AB-II", "start": "2010-08-02", "end": "2010-09-28"},
    "EHB0824": {"scenario": "AB-I", "start": "2010-07-22", "end": "2010-07-29"},
    "EHD0584": {"scenario": "AB-I", "start": "2010-10-02", "end": "2010-10-08"},
    "FMG0527": {"scenario": "AB-I", "start": "2011-01-05", "end": "2011-01-12"},
    "FSC0601": {"scenario": "AB-II", "start": "2011-01-18", "end": "2011-03-17"},
    "FTM0406": {"scenario": "AB-I", "start": "2010-11-25", "end": "2010-12-02"},
    "GHL0460": {"scenario": "AB-I", "start": "2010-11-09", "end": "2010-11-09"},
    "GTD0219": {"scenario": "AB-III", "start": "2010-06-17", "end": "2010-06-18"},
    "HBO0413": {"scenario": "AB-II", "start": "2011-02-14", "end": "2011-04-08"},
    "HJB0742": {"scenario": "AB-I", "start": "2010-11-19", "end": "2010-11-25"},
    "HXL0968": {"scenario": "AB-II", "start": "2010-08-31", "end": "2010-10-28"},
    "IJM0776": {"scenario": "AB-II", "start": "2010-07-06", "end": "2010-09-01"},
    "IKR0401": {"scenario": "AB-II", "start": "2010-12-27", "end": "2011-02-17"},
    "IUB0565": {"scenario": "AB-II", "start": "2010-10-06", "end": "2010-11-30"},
    "JGT0221": {"scenario": "AB-III", "start": "2010-07-15", "end": "2010-07-16"},
    "JJM0203": {"scenario": "AB-II", "start": "2010-09-02", "end": "2010-10-19"},
    "JLM0364": {"scenario": "AB-III", "start": "2011-04-28", "end": "2011-04-29"},
    "JMB0308": {"scenario": "AB-I", "start": "2010-07-14", "end": "2010-07-21"},
    "JRG0207": {"scenario": "AB-I", "start": "2011-01-19", "end": "2011-01-26"},
    "JTM0223": {"scenario": "AB-III", "start": "2010-07-22", "end": "2010-07-23"},
    "KLH0596": {"scenario": "AB-I", "start": "2011-02-12", "end": "2011-02-12"},
    "KPC0073": {"scenario": "AB-I", "start": "2010-07-07", "end": "2010-07-15"},
    "KRL0501": {"scenario": "AB-II", "start": "2010-11-22", "end": "2011-01-19"},
    "LCC0819": {"scenario": "AB-II", "start": "2010-06-16", "end": "2010-08-10"},
    "LJR0523": {"scenario": "AB-I", "start": "2010-07-31", "end": "2010-08-11"},
    "LQC0479": {"scenario": "AB-I", "start": "2010-09-14", "end": "2010-09-22"},
    "MAR0955": {"scenario": "AB-I", "start": "2011-02-08", "end": "2011-02-11"},
    "MAS0025": {"scenario": "AB-I", "start": "2010-09-29", "end": "2010-09-30"},
    "MCF0600": {"scenario": "AB-I", "start": "2010-09-20", "end": "2010-09-23"},
    "MDH0580": {"scenario": "AB-II", "start": "2011-01-04", "end": "2011-03-03"},
    "MOS0047": {"scenario": "AB-II", "start": "2010-07-15", "end": "2010-09-10"},
    "MPM0220": {"scenario": "AB-III", "start": "2010-11-04", "end": "2010-11-05"},
    "MSO0222": {"scenario": "AB-III", "start": "2010-12-09", "end": "2010-12-10"},
    "MYD0978": {"scenario": "AB-I", "start": "2010-12-13", "end": "2010-12-18"},
    "NWT0098": {"scenario": "AB-II", "start": "2011-02-07", "end": "2011-04-05"},
    "PNL0301": {"scenario": "AB-II", "start": "2010-06-14", "end": "2010-08-03"},
    "PPF0435": {"scenario": "AB-I", "start": "2011-02-09", "end": "2011-02-09"},
    "PSF0133": {"scenario": "AB-II", "start": "2010-08-02", "end": "2010-09-29"},
    "RAB0589": {"scenario": "AB-I", "start": "2010-09-13", "end": "2010-09-23"},
    "RAR0725": {"scenario": "AB-II", "start": "2010-07-06", "end": "2010-08-19"},
    "RGG0064": {"scenario": "AB-I", "start": "2010-10-20", "end": "2010-10-27"},
    "RHL0992": {"scenario": "AB-II", "start": "2010-07-13", "end": "2010-09-09"},
    "RKD0604": {"scenario": "AB-I", "start": "2010-07-13", "end": "2010-07-20"},
    "RMW0542": {"scenario": "AB-II", "start": "2010-06-21", "end": "2010-08-18"},
    "TAP0551": {"scenario": "AB-I", "start": "2010-10-23", "end": "2010-10-29"},
    "TNM0961": {"scenario": "AB-II", "start": "2010-10-15", "end": "2010-12-09"},
    "VSS0154": {"scenario": "AB-II", "start": "2010-09-07", "end": "2010-10-29"},
    "WDD0366": {"scenario": "AB-I", "start": "2011-02-24", "end": "2011-03-03"},
    "XHW0498": {"scenario": "AB-II", "start": "2010-08-09", "end": "2010-10-06"},
}

# Labeling function
def get_label(user, session_date):
    """
    Returns 1 if the user was conducting malicious activity on that date, else 0.
    session_date should be a datetime.date object.
    """
    import datetime
    if user not in MALICIOUS_USERS:
        return 0
    info = MALICIOUS_USERS[user]
    start = datetime.date.fromisoformat(info["start"])
    end   = datetime.date.fromisoformat(info["end"])
    if start <= session_date <= end:
        return 1
    return 0
