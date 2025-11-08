import os
import time
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import psutil
import win32api
import win32file
from config import RESTRICTED_PATHS, MONITORED_EXTENSIONS
import logging

class FileAccessHandler(FileSystemEventHandler):
    def __init__(self, threat_detector):
        self.threat_detector = threat_detector
        self.restricted_paths = RESTRICTED_PATHS
    
    def on_accessed(self, event):
        if not event.is_directory:
            self.check_file_access(event.src_path, 'file_access')
    
    def on_modified(self, event):
        if not event.is_directory:
            self.check_file_access(event.src_path, 'file_modify')
    
    def on_deleted(self, event):
        if not event.is_directory:
            self.check_file_access(event.src_path, 'file_delete')
    
    def check_file_access(self, file_path, event_type):
        """Check if file access should be blocked or alerted"""
        try:
            # Get current user (simplified - in real system would get from session)
            current_user_id = 1  # Default admin user for demo
            
            # Check if file is restricted
            is_restricted = any(file_path.startswith(path) for path in self.restricted_paths)
            
            if is_restricted:
                # Block access and create alert
                self.threat_detector.handle_restricted_access(
                    current_user_id, file_path, event_type
                )
            else:
                # Log normal activity
                self.threat_detector.log_file_activity(
                    current_user_id, file_path, event_type
                )
        
        except Exception as e:
            logging.error(f"File access check error: {e}")

class USBMonitor:
    def __init__(self, threat_detector):
        self.threat_detector = threat_detector
        self.known_drives = set()
        self.monitoring = False
        self.update_known_drives()
    
    def update_known_drives(self):
        """Update list of known drives"""
        drives = win32api.GetLogicalDriveStrings()
        self.known_drives = set(drives.split('\000')[:-1])
    
    def start_monitoring(self):
        """Start USB monitoring in separate thread"""
        self.monitoring = True
        thread = threading.Thread(target=self._monitor_usb)
        thread.daemon = True
        thread.start()
    
    def stop_monitoring(self):
        """Stop USB monitoring"""
        self.monitoring = False
    
    def _monitor_usb(self):
        """Monitor for USB device changes"""
        while self.monitoring:
            try:
                current_drives = set(win32api.GetLogicalDriveStrings().split('\000')[:-1])
                
                # Check for new drives (USB connected)
                new_drives = current_drives - self.known_drives
                for drive in new_drives:
                    if self._is_removable_drive(drive):
                        self.threat_detector.handle_usb_connection(drive)
                
                # Check for removed drives (USB disconnected)
                removed_drives = self.known_drives - current_drives
                for drive in removed_drives:
                    self.threat_detector.handle_usb_disconnection(drive)
                
                self.known_drives = current_drives
                time.sleep(2)  # Check every 2 seconds
                
            except Exception as e:
                logging.error(f"USB monitoring error: {e}")
                time.sleep(5)
    
    def _is_removable_drive(self, drive):
        """Check if drive is removable (USB/Mobile)"""
        try:
            drive_type = win32file.GetDriveType(drive)
            if drive_type == win32file.DRIVE_REMOVABLE:
                return True
            
            # Additional check for MTP/PTP devices (mobile phones)
            import wmi
            c = wmi.WMI()
            for item in c.Win32_DiskDrive():
                if 'USB' in item.InterfaceType or 'Portable Device' in item.Caption:
                    for partition in item.associators("Win32_DiskDriveToDiskPartition"):
                        for logical_disk in partition.associators("Win32_LogicalDiskToPartition"):
                            if logical_disk.Caption == drive:
                                return True
            return False
        except Exception as e:
            logging.error(f"Error checking removable drive: {e}")
            return False

class FileMonitor:
    def __init__(self, threat_detector):
        self.threat_detector = threat_detector
        self.observer = Observer()
        self.usb_monitor = USBMonitor(threat_detector)
        self.handler = FileAccessHandler(threat_detector)
    
    def start_monitoring(self):
        """Start file system monitoring"""
        try:
            # Monitor system drives
            for drive in ['C:\\', 'D:\\', 'E:\\']:
                if os.path.exists(drive):
                    self.observer.schedule(self.handler, drive, recursive=True)
            
            self.observer.start()
            self.usb_monitor.start_monitoring()
            logging.info("File monitoring started")
            
        except Exception as e:
            logging.error(f"Error starting file monitor: {e}")
    
    def stop_monitoring(self):
        """Stop file system monitoring"""
        try:
            self.observer.stop()
            self.observer.join()
            self.usb_monitor.stop_monitoring()
            logging.info("File monitoring stopped")
        except Exception as e:
            logging.error(f"Error stopping file monitor: {e}")
    
    def block_file_access(self, file_path):
        """Block access to a specific file (Windows specific)"""
        try:
            # In a real implementation, this would use Windows API
            # to deny file access permissions
            logging.warning(f"BLOCKED: Access to {file_path}")
            return True
        except Exception as e:
            logging.error(f"Error blocking file access: {e}")
            return False