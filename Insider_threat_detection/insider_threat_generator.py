import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import uuid
import random
import json

class InsiderThreatDataGenerator:
    def __init__(self, seed=42):
        np.random.seed(seed)
        random.seed(seed)
        
        self.employee_ip = "10.0.5.17"
        self.device_id = str(uuid.UUID('12345678-1234-5678-9abc-123456789012'))
        self.username = "user_001"
        self.start_date = datetime(2025, 7, 1)
        self.days = 60
        self.avg_events_per_day = 200
        
        self.event_types = [
            'login_success', 'login_failed', 'logout', 'file_open', 'file_modify', 
            'file_delete', 'process_start', 'process_stop', 'network_conn', 
            'download', 'upload', 'email_send', 'email_receive', 'usb_insert', 
            'usb_remove', 'privilege_escalation', 'config_change', 'print_job', 
            'clipboard_copy', 'clipboard_paste'
        ]
        
        self.processes = [
            'chrome.exe', 'firefox.exe', 'outlook.exe', 'word.exe', 'excel.exe',
            'notepad.exe', 'explorer.exe', 'cmd.exe', 'powershell.exe', 'python.exe',
            'java.exe', 'putty.exe', 'rsync.exe', 'winrar.exe', 'vlc.exe'
        ]
        
        self.file_extensions = ['.docx', '.xlsx', '.pdf', '.txt', '.csv', '.pptx', '.zip', '.exe', '.dll']
        self.protocols = ['HTTP', 'HTTPS', 'FTP', 'SSH', 'SMTP', 'POP3', 'IMAP', 'TCP', 'UDP']
        

        
    def generate_hash(self):
        return ''.join(random.choices('0123456789abcdef', k=32)) if random.random() > 0.3 else ''
    
    def generate_filename(self, suspicious=False):
        if suspicious:
            suspicious_names = ['passwords.txt', 'confidential.docx', 'salary_data.xlsx', 
                              'customer_db.csv', 'source_code.zip', 'admin_keys.txt']
            return random.choice(suspicious_names)
        
        normal_names = ['report.docx', 'data.xlsx', 'presentation.pptx', 'notes.txt', 
                       'image.jpg', 'document.pdf', 'backup.zip']
        return random.choice(normal_names)
    
    def generate_file_path(self, filename):
        paths = [f'C:\\Users\\user_001\\Documents\\{filename}',
                f'C:\\Users\\user_001\\Desktop\\{filename}',
                f'C:\\Users\\user_001\\Downloads\\{filename}',
                f'D:\\Projects\\{filename}',
                f'E:\\Backup\\{filename}']
        return random.choice(paths)
    
    def generate_dest_ip(self, suspicious=False):
        if suspicious:
            # Foreign/suspicious IPs
            suspicious_ips = ['185.220.101.42', '91.203.67.89', '103.224.182.251', 
                            '45.142.214.123', '194.147.78.45']
            return random.choice(suspicious_ips)
        
        # Normal internal/external IPs
        internal_ips = [f'10.0.{random.randint(1,10)}.{random.randint(1,254)}' for _ in range(5)]
        external_ips = ['8.8.8.8', '1.1.1.1', '208.67.222.222', '74.125.224.72']
        return random.choice(internal_ips + external_ips)
    
    def generate_url(self, suspicious=False):
        if suspicious:
            return random.choice(['http://suspicious-site.com/upload', 'ftp://data-exfil.net/files',
                                'https://temp-share.org/download'])
        return random.choice(['https://company-portal.com', 'https://outlook.office365.com',
                            'https://github.com', 'https://stackoverflow.com'])
    
    def get_work_hour_weight(self, hour):
        # Higher activity during work hours (8-18), lower at night
        if 8 <= hour <= 18:
            return 1.0
        elif 6 <= hour < 8 or 18 < hour <= 22:
            return 0.3
        else:
            return 0.1
    
    def get_day_weight(self, weekday):
        # Monday=0, Sunday=6. Lower activity on weekends
        if weekday < 5:  # Weekdays
            return 1.0 if weekday != 0 else 1.2  # Monday slightly higher
        else:  # Weekend
            return 0.2
    
    def generate_normal_event(self, timestamp):
        event_type = random.choice(self.event_types)
        
        event = {
            'timestamp': timestamp.strftime('%Y-%m-%dT%H:%M:%S'),
            'employee_ip': self.employee_ip,
            'device_id': self.device_id,
            'username_anonymized': self.username,
            'event_type': event_type,
            'process_name': '',
            'process_hash': '',
            'filename': '',
            'file_path': '',
            'bytes_transferred': 0,
            'dest_ip': '',
            'dest_port': 0,
            'url': '',
            'protocol': '',
            'outcome': 'success',

            'event_id': str(uuid.uuid4())
        }
        
        # Fill event-specific fields
        if event_type in ['process_start', 'process_stop']:
            event['process_name'] = random.choice(self.processes)
            event['process_hash'] = self.generate_hash()
        elif event_type in ['file_open', 'file_modify', 'file_delete']:
            event['filename'] = self.generate_filename()
            event['file_path'] = self.generate_file_path(event['filename'])
        elif event_type in ['download', 'upload']:
            event['bytes_transferred'] = random.randint(1024, 50*1024*1024)
            event['url'] = self.generate_url()
        elif event_type == 'network_conn':
            event['dest_ip'] = self.generate_dest_ip()
            event['dest_port'] = random.choice([80, 443, 22, 21, 25, 993, 995])
            event['protocol'] = random.choice(self.protocols)
        elif event_type == 'login_failed':
            event['outcome'] = random.choice(['wrong_password', 'account_locked'])
        elif event_type in ['usb_insert', 'usb_remove']:
            event['bytes_transferred'] = random.randint(0, 16*1024*1024*1024) if event_type == 'usb_remove' else 0
            
        return event
    
    def generate_anomalous_event(self, timestamp):
        anomaly_type = random.choice([
            'large_off_hours_transfer', 'usb_exfil', 'failed_login_burst', 
            'privilege_escalation', 'suspicious_download', 'unusual_process',
            'foreign_ip_transfer', 'unusual_port'
        ])
        
        event = self.generate_normal_event(timestamp)

        
        if anomaly_type == 'large_off_hours_transfer':
            event['event_type'] = 'upload'
            event['bytes_transferred'] = random.randint(500*1024*1024, 5*1024*1024*1024)
            event['dest_ip'] = self.generate_dest_ip(suspicious=True)
            event['url'] = self.generate_url(suspicious=True)
            reason = f"Large data transfer ({event['bytes_transferred']//1024//1024}MB) to foreign IP during off-hours"
            
        elif anomaly_type == 'usb_exfil':
            event['event_type'] = 'usb_remove'
            event['bytes_transferred'] = random.randint(1*1024*1024*1024, 32*1024*1024*1024)
            reason = f"Large USB data exfiltration ({event['bytes_transferred']//1024//1024//1024}GB)"
            
        elif anomaly_type == 'failed_login_burst':
            event['event_type'] = 'login_failed'
            event['outcome'] = 'wrong_password'
            reason = "Part of failed login burst pattern"
            
        elif anomaly_type == 'privilege_escalation':
            event['event_type'] = 'privilege_escalation'
            event['outcome'] = 'success'
            reason = "Successful privilege escalation"
            
        elif anomaly_type == 'suspicious_download':
            event['event_type'] = 'download'
            event['filename'] = self.generate_filename(suspicious=True)
            event['file_path'] = self.generate_file_path(event['filename'])
            event['bytes_transferred'] = random.randint(1024, 100*1024*1024)
            reason = f"Download of sensitive file: {event['filename']}"
            
        elif anomaly_type == 'unusual_process':
            event['event_type'] = 'process_start'
            event['process_name'] = random.choice(['powershell.exe', 'rsync.exe', 'putty.exe'])
            event['process_hash'] = self.generate_hash()
            reason = f"Unusual process execution: {event['process_name']}"
            
        elif anomaly_type == 'foreign_ip_transfer':
            event['event_type'] = 'network_conn'
            event['dest_ip'] = self.generate_dest_ip(suspicious=True)
            event['dest_port'] = random.choice([8080, 9999, 4444, 1337])
            event['protocol'] = 'TCP'
            reason = f"Connection to foreign IP {event['dest_ip']} on unusual port {event['dest_port']}"
            
        elif anomaly_type == 'unusual_port':
            event['event_type'] = 'upload'
            event['dest_port'] = random.choice([8080, 9999, 4444, 1337, 31337])
            event['bytes_transferred'] = random.randint(10*1024*1024, 500*1024*1024)
            reason = f"Data exfiltration via unusual port {event['dest_port']}"
        

        return event
    
    def generate_dataset(self):
        events = []
        
        for day in range(self.days):
            current_date = self.start_date + timedelta(days=day)
            day_weight = self.get_day_weight(current_date.weekday())
            daily_events = int(self.avg_events_per_day * day_weight * random.uniform(0.8, 1.2))
            
            for _ in range(daily_events):
                # Generate random time within the day
                hour = random.randint(0, 23)
                minute = random.randint(0, 59)
                second = random.randint(0, 59)
                
                # Apply hour weighting - skip event based on probability
                if random.random() > self.get_work_hour_weight(hour):
                    continue
                
                timestamp = current_date.replace(hour=hour, minute=minute, second=second)
                
                # Generate mix of normal and anomalous events (unlabeled)
                if random.random() < 0.02:
                    event = self.generate_anomalous_event(timestamp)
                else:
                    event = self.generate_normal_event(timestamp)
                
                events.append(event)
        
        # Sort by timestamp
        events.sort(key=lambda x: x['timestamp'])
        return pd.DataFrame(events)

def main():
    generator = InsiderThreatDataGenerator(seed=42)
    df = generator.generate_dataset()
    
    # Save CSV
    df.to_csv('insider_threat_dataset.csv', index=False)
    
    # Save JSONL
    with open('insider_threat_dataset.jsonl', 'w') as f:
        for _, row in df.iterrows():
            f.write(json.dumps(row.to_dict()) + '\n')
    

    
    print(f"Generated {len(df)} events over {generator.days} days")
    print("Dataset generated for unsupervised learning (no labels)")
    print(f"Date range: {df['timestamp'].min()} to {df['timestamp'].max()}")
    print("\nFirst 50 rows:")
    print(df.head(50).to_string())

if __name__ == "__main__":
    main()