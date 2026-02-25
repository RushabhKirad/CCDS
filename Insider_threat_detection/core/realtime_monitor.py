import os
import time
import threading
import psutil
import win32api
import win32file
import win32con
import win32security
from datetime import datetime
import logging

class RealTimeFileMonitor:
    def __init__(self, threat_detector):
        self.threat_detector = threat_detector
        self.monitoring = False
        self.restricted_paths = set()
        self.monitored_processes = {}
        
    def start_monitoring(self):
        """Start real-time file monitoring"""
        self.monitoring = True
        
        # Start process monitoring thread
        process_thread = threading.Thread(target=self._monitor_processes)
        process_thread.daemon = True
        process_thread.start()
        
        # Start file access monitoring thread
        file_thread = threading.Thread(target=self._monitor_file_access)
        file_thread.daemon = True
        file_thread.start()
        
        logging.info("Real-time file monitoring started")
    
    def _monitor_processes(self):
        """Monitor process file access in real-time"""
        while self.monitoring:
            try:
                for proc in psutil.process_iter(['pid', 'name', 'open_files']):
                    try:
                        if proc.info['open_files']:
                            for file_info in proc.info['open_files']:
                                file_path = file_info.path
                                if self._is_restricted_path(file_path):
                                    self._trigger_restriction_alert(file_path, 'file_access')
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                time.sleep(1)  # Check every second
            except Exception as e:
                logging.error(f"Process monitoring error: {e}")
                time.sleep(5)
    
    def _monitor_file_access(self):
        """Monitor file system access using Windows API"""
        while self.monitoring:
            try:
                # Update restricted paths from database
                self._update_restricted_paths()
                
                # Check for new file handles
                for path in self.restricted_paths:
                    if os.path.exists(path):
                        try:
                            # Try to get file attributes (this triggers access detection)
                            attrs = win32api.GetFileAttributes(path)
                            
                            # Check if file is currently being accessed
                            try:
                                handle = win32file.CreateFile(
                                    path,
                                    win32con.GENERIC_READ,
                                    0,  # No sharing - will fail if file is open
                                    None,
                                    win32con.OPEN_EXISTING,
                                    win32con.FILE_ATTRIBUTE_NORMAL,
                                    None
                                )
                                win32api.CloseHandle(handle)
                            except Exception:
                                # File is being accessed - trigger alert
                                self._trigger_restriction_alert(path, 'file_open')
                                
                        except Exception:
                            continue
                
                time.sleep(0.5)  # Fast checking
            except Exception as e:
                logging.error(f"File access monitoring error: {e}")
                time.sleep(2)
    
    def _update_restricted_paths(self):
        """Update restricted paths from database"""
        try:
            restricted = self.threat_detector.db.get_restricted_resources()
            if restricted:
                self.restricted_paths = {r['resource_path'] for r in restricted}
            else:
                # Default paths if database unavailable
                self.restricted_paths = {'C:\\$Recycle.Bin', 'C:\\confidential', 'C:\\sensitive'}
        except Exception:
            self.restricted_paths = {'C:\\$Recycle.Bin', 'C:\\confidential', 'C:\\sensitive'}
    
    def _is_restricted_path(self, file_path):
        """Check if file path is restricted"""
        if not file_path:
            return False
        
        for restricted_path in self.restricted_paths:
            if file_path.lower().startswith(restricted_path.lower()):
                return True
        return False
    
    def _trigger_restriction_alert(self, file_path, event_type):
        """Trigger restriction alert"""
        try:
            current_time = time.time()
            
            # Avoid duplicate alerts (within 5 seconds)
            cache_key = f"{file_path}_{event_type}"
            if hasattr(self, '_last_alerts'):
                if cache_key in self._last_alerts:
                    if current_time - self._last_alerts[cache_key] < 5:
                        return
            else:
                self._last_alerts = {}
            
            self._last_alerts[cache_key] = current_time
            
            # Trigger the alert
            self.threat_detector.handle_restricted_access(1, file_path, event_type)
            logging.warning(f"REAL-TIME RESTRICTION ALERT: {event_type} on {file_path}")
            
        except Exception as e:
            logging.error(f"Alert trigger error: {e}")
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring = False
        logging.info("Real-time file monitoring stopped")

class RealTimeUSBMonitor:
    def __init__(self, threat_detector):
        self.threat_detector = threat_detector
        self.monitoring = False
        self.known_drives = set()
    
    def start_monitoring(self):
        """Start USB monitoring"""
        self.monitoring = True
        self._update_known_drives()
        
        usb_thread = threading.Thread(target=self._monitor_usb)
        usb_thread.daemon = True
        usb_thread.start()
        
        logging.info("Real-time USB monitoring started")
    
    def _monitor_usb(self):
        """Monitor USB devices"""
        while self.monitoring:
            try:
                current_drives = set(win32api.GetLogicalDriveStrings().split('\000')[:-1])
                
                # New USB devices
                new_drives = current_drives - self.known_drives
                for drive in new_drives:
                    if self._is_usb_drive(drive):
                        label = self._get_drive_label(drive)
                        device_info = {'drive': drive, 'label': label, 'type': 'USB Storage'}
                        self.threat_detector.handle_usb_connection_fast(drive, device_info)
                        logging.warning(f"USB CONNECTED: {drive} ({label})")
                
                # Removed USB devices
                removed_drives = self.known_drives - current_drives
                for drive in removed_drives:
                    self.threat_detector.handle_usb_disconnection_fast(drive)
                    logging.info(f"USB REMOVED: {drive}")
                
                self.known_drives = current_drives
                time.sleep(1)
                
            except Exception as e:
                logging.error(f"USB monitoring error: {e}")
                time.sleep(3)
    
    def _is_usb_drive(self, drive):
        """Check if drive is USB"""
        try:
            drive_type = win32file.GetDriveType(drive)
            return drive_type == win32file.DRIVE_REMOVABLE
        except:
            return False
    
    def _get_drive_label(self, drive):
        """Get drive label"""
        try:
            volume_info = win32api.GetVolumeInformation(drive)
            return volume_info[0] if volume_info and volume_info[0] else "USB Device"
        except:
            return "USB Device"
    
    def _update_known_drives(self):
        """Update known drives"""
        try:
            drives = win32api.GetLogicalDriveStrings().split('\000')[:-1]
            self.known_drives = set(drives)
        except:
            self.known_drives = set()
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring = False
        logging.info("USB monitoring stopped")

class ProfessionalMonitoringSystem:
    def __init__(self, threat_detector):
        self.threat_detector = threat_detector
        self.file_monitor = RealTimeFileMonitor(threat_detector)
        self.usb_monitor = RealTimeUSBMonitor(threat_detector)
        self.monitoring = False
    
    def start_all_monitoring(self):
        """Start all monitoring systems"""
        try:
            self.file_monitor.start_monitoring()
            self.usb_monitor.start_monitoring()
            self.monitoring = True
            
            logging.info("🚀 PROFESSIONAL MONITORING SYSTEM ACTIVE")
            logging.info("✅ Real-time file access detection")
            logging.info("✅ Real-time USB detection")
            logging.info("✅ Process monitoring")
            
        except Exception as e:
            logging.error(f"Monitoring start error: {e}")
    
    def stop_all_monitoring(self):
        """Stop all monitoring"""
        try:
            self.file_monitor.stop_monitoring()
            self.usb_monitor.stop_monitoring()
            self.monitoring = False
            logging.info("Monitoring system stopped")
        except Exception as e:
            logging.error(f"Monitoring stop error: {e}")
    
    def is_monitoring(self):
        """Check if monitoring is active"""
        return self.monitoring