# Insider Threat Detection Dataset

## Overview
This dataset contains synthetic, anonymized security logs for insider threat detection research. It simulates 60 days of activity from a single employee workstation (IP: 10.0.5.17) with realistic behavioral patterns and injected anomalies.

## Dataset Specifications
- **Time Range**: 2025-07-01 to 2025-08-29 (60 days)
- **Employee IP**: 10.0.5.17 (fixed)
- **Total Events**: ~12,000 (average 200/day)
- **Anomalous Events**: ~2% (unlabeled for unsupervised learning)
- **Format**: CSV and JSONL

## Column Descriptions

| Column | Type | Description |
|--------|------|-------------|
| timestamp | string | ISO 8601 timestamp (YYYY-MM-DDTHH:MM:SS) |
| employee_ip | string | Fixed IP address (10.0.5.17) |
| device_id | string | UUID of the employee device |
| username_anonymized | string | Anonymized username (user_001) |
| event_type | string | Type of security event (see Event Types below) |
| process_name | string | Name of process (if applicable) |
| process_hash | string | 32-char hex hash of process (if applicable) |
| filename | string | Name of file involved (if applicable) |
| file_path | string | Full path to file (if applicable) |
| bytes_transferred | integer | Number of bytes transferred (if applicable) |
| dest_ip | string | Destination IP address (if applicable) |
| dest_port | integer | Destination port number (if applicable) |
| url | string | URL accessed (if applicable) |
| protocol | string | Network protocol used (if applicable) |
| outcome | string | Result of operation (success, wrong_password, denied, account_locked) |

| event_id | string | Unique UUID for each event |

## Event Types
- login_success, login_failed, logout
- file_open, file_modify, file_delete
- process_start, process_stop
- network_conn, download, upload
- email_send, email_receive
- usb_insert, usb_remove
- privilege_escalation, config_change
- print_job, clipboard_copy, clipboard_paste

## Behavioral Patterns
- **Diurnal Cycles**: Higher activity during work hours (8AM-6PM), minimal activity at night
- **Weekly Patterns**: Increased activity on Mondays, reduced activity on weekends
- **Natural Variation**: Daily event counts vary ±20% from average

## Anomalous Patterns (Unlabeled)
The dataset contains realistic insider threat scenarios mixed with normal behavior:
- Large off-hours data transfers to foreign IPs
- USB data exfiltration (large volumes) 
- Failed login bursts followed by success
- Successful privilege escalations
- Downloads of sensitive files
- Unusual process executions (PowerShell, rsync, PuTTY)
- Connections to foreign IPs on unusual ports
- Data exfiltration via non-standard ports

**Note**: These patterns are unlabeled - the model must learn to detect them unsupervised.

## Files Included
- `insider_logs_10.0.5.17_60days.csv` - Main dataset in CSV format
- `insider_logs_10.0.5.17_60days.jsonl` - Main dataset in JSONL format

- `insider_threat_generator.py` - Python script to regenerate dataset
- `README.md` - This documentation

## Customization
To modify the dataset parameters, edit the `InsiderThreatDataGenerator` class:

```python
# Change IP address
self.employee_ip = "192.168.1.100"

# Change date range
self.start_date = datetime(2024, 1, 1)
self.days = 90

# Change event volume
self.avg_events_per_day = 300

# Change anomalous event rate (in generate_dataset method)
if random.random() < 0.05:  # 5% anomalous events (unlabeled)
```

## Reproducibility
The generator uses a fixed seed (42) for reproducible results. Change the seed parameter to generate different variations:

```python
generator = InsiderThreatDataGenerator(seed=123)
```

## Ethical Use Statement
This dataset contains NO real personally identifiable information (PII). All data is synthetically generated for research purposes. The dataset is designed for:
- Academic research in cybersecurity
- Development of insider threat detection models
- Benchmarking security analytics tools

Users should ensure compliance with their institution's data use policies and applicable regulations when using this dataset for research or commercial purposes.

## Data Privacy
- No real employee data was used
- All usernames, IPs, and identifiers are synthetic
- File names and paths are generic placeholders
- Process hashes are randomly generated