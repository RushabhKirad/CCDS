import os
import threading
import time
from collections import defaultdict
import win32api
import win32file
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import logging

class FastFileHandler(FileSystemEventHandler):
    def __init__(self, threat_detector):
        self.threat_detector = threat_detector
        self.event_cache = defaultdict(list)
        self.last_process_time = time.time()
        self.batch_size = 50
        
    def on_any_event(self, event):
        if event.is_directory:
            return
            
        # Cache events for batch processing
        self.event_cache[event.event_type].append({
            'path': event.src_path,
            'timestamp': time.time()
        })
        
        # Process batch if cache is full or time elapsed
        if (len(self.event_cache) >= self.batch_size or 
            time.time() - self.last_process_time > 2):
            self.process_batch()
    
    def process_batch(self):
        """Process cached events in batch for better performance"""
        try:
            for event_type, events in self.event_cache.items():
                for event in events:
                    self.threat_detector.check_file_access_fast(
                        event['path'], 
                        event_type,
                        event['timestamp']
                    )
            
            self.event_cache.clear()
            self.last_process_time = time.time()
            
        except Exception as e:
            logging.error(f"Batch processing error: {e}")

class FastUSBMonitor:
    def __init__(self, threat_detector):
        self.threat_detector = threat_detector
        self.known_drives = set()
        self.monitoring = False
        self.check_interval = 1  # Check every 1 second for faster detection
        
    def start_monitoring(self):
        self.monitoring = True
        self.update_known_drives()
        thread = threading.Thread(target=self._fast_monitor_usb)
        thread.daemon = True
        thread.start()
        logging.info("Fast USB monitoring started")
    
    def _fast_monitor_usb(self):
        while self.monitoring:
            try:
                current_drives = set(win32api.GetLogicalDriveStrings().split('\000')[:-1])
                
                # Check for new USB devices
                new_drives = current_drives - self.known_drives
                for drive in new_drives:
                    if self._is_usb_drive(drive):
                        self.threat_detector.handle_usb_connection_fast(drive)
                
                # Check for removed USB devices
                removed_drives = self.known_drives - current_drives
                for drive in removed_drives:
                    self.threat_detector.handle_usb_disconnection_fast(drive)
                
                self.known_drives = current_drives
                time.sleep(self.check_interval)
                
            except Exception as e:
                logging.error(f"Fast USB monitoring error: {e}")
                time.sleep(5)
    
    def _is_usb_drive(self, drive):
        try:
            drive_type = win32file.GetDriveType(drive)
            return drive_type == win32file.DRIVE_REMOVABLE
        except:
            return False
    
    def update_known_drives(self):
        drives = win32api.GetLogicalDriveStrings()
        self.known_drives = set(drives.split('\000')[:-1])
    
    def stop_monitoring(self):
        self.monitoring = False
        logging.info("Fast USB monitoring stopped")

class FastNetworkMonitor:
    def __init__(self, threat_detector):
        self.threat_detector = threat_detector
        self.monitoring = False
        self.last_network_stats = {}
        self.check_interval = 3  # Check every 3 seconds
        
    def start_monitoring(self):
        self.monitoring = True
        thread = threading.Thread(target=self._monitor_network)
        thread.daemon = True
        thread.start()
        logging.info("Fast network monitoring started")
    
    def _monitor_network(self):
        while self.monitoring:
            try:
                # Get current network stats
                net_stats = psutil.net_io_counters(pernic=True)
                
                for interface, stats in net_stats.items():
                    if interface in self.last_network_stats:
                        # Calculate bytes transferred since last check
                        bytes_sent = stats.bytes_sent - self.last_network_stats[interface].bytes_sent
                        bytes_recv = stats.bytes_recv - self.last_network_stats[interface].bytes_recv
                        
                        # Check for large transfers (>10MB in 3 seconds = suspicious)
                        if bytes_sent > 10 * 1024 * 1024 or bytes_recv > 10 * 1024 * 1024:
                            self.threat_detector.handle_network_spike_fast(
                                interface, bytes_sent, bytes_recv
                            )
                    
                    self.last_network_stats[interface] = stats
                
                time.sleep(self.check_interval)
                
            except Exception as e:
                logging.error(f"Network monitoring error: {e}")
                time.sleep(10)
    
    def stop_monitoring(self):
        self.monitoring = False
        logging.info("Fast network monitoring stopped")

class FastProcessMonitor:
    def __init__(self, threat_detector):
        self.threat_detector = threat_detector
        self.monitoring = False
        self.known_processes = set()
        self.suspicious_processes = [
            'powershell.exe', 'cmd.exe', 'putty.exe', 'winscp.exe',
            'filezilla.exe', 'rsync.exe', 'scp.exe', 'psexec.exe'
        ]
        
    def start_monitoring(self):
        self.monitoring = True
        self.update_known_processes()
        thread = threading.Thread(target=self._monitor_processes)
        thread.daemon = True
        thread.start()
        logging.info("Fast process monitoring started")
    
    def _monitor_processes(self):
        while self.monitoring:
            try:
                current_processes = set()
                
                for proc in psutil.process_iter(['pid', 'name', 'exe']):
                    try:
                        proc_info = proc.info
                        proc_id = (proc_info['pid'], proc_info['name'])
                        current_processes.add(proc_id)
                        
                        # Check for new suspicious processes
                        if (proc_id not in self.known_processes and 
                            proc_info['name'].lower() in self.suspicious_processes):
                            
                            self.threat_detector.handle_suspicious_process_fast(
                                proc_info['name'], 
                                proc_info['exe'] or 'Unknown'
                            )
                    
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                self.known_processes = current_processes
                time.sleep(2)  # Check every 2 seconds
                
            except Exception as e:
                logging.error(f"Process monitoring error: {e}")
                time.sleep(5)
    
    def update_known_processes(self):
        self.known_processes = set()
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                proc_info = proc.info
                self.known_processes.add((proc_info['pid'], proc_info['name']))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    
    def stop_monitoring(self):
        self.monitoring = False
        logging.info("Fast process monitoring stopped")

class FastMonitoringSystem:
    def __init__(self, threat_detector):
        self.threat_detector = threat_detector
        self.file_observer = Observer()
        self.file_handler = FastFileHandler(threat_detector)
        self.usb_monitor = FastUSBMonitor(threat_detector)
        self.network_monitor = FastNetworkMonitor(threat_detector)
        self.process_monitor = FastProcessMonitor(threat_detector)
        self.monitoring = False
    
    def start_all_monitoring(self):
        """Start all fast monitoring components"""
        try:
            # Start file monitoring
            drives_to_monitor = ['C:\\', 'D:\\', 'E:\\']
            for drive in drives_to_monitor:
                if os.path.exists(drive):
                    self.file_observer.schedule(self.file_handler, drive, recursive=True)
            
            self.file_observer.start()
            
            # Start other monitors
            self.usb_monitor.start_monitoring()
            self.network_monitor.start_monitoring()
            self.process_monitor.start_monitoring()
            
            self.monitoring = True
            logging.info("Fast monitoring system started - All components active")
            
        except Exception as e:
            logging.error(f"Error starting fast monitoring: {e}")
    
    def stop_all_monitoring(self):
        """Stop all monitoring components"""
        try:
            self.file_observer.stop()
            self.file_observer.join()
            
            self.usb_monitor.stop_monitoring()
            self.network_monitor.stop_monitoring()
            self.process_monitor.stop_monitoring()
            
            self.monitoring = False
            logging.info("Fast monitoring system stopped")
            
        except Exception as e:
            logging.error(f"Error stopping fast monitoring: {e}")
    
    def is_monitoring(self):
        return self.monitoring