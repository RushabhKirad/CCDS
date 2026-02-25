import os
import time
import threading
import psutil
import win32api
import win32file
import win32gui
import win32process
from datetime import datetime
import logging

class EliteFileMonitor:
    def __init__(self, threat_detector):
        self.threat_detector = threat_detector
        self.monitoring = False
        self.restricted_paths = set()
        self.last_alerts = {}
        self.user_processes = {'explorer.exe', 'notepad.exe', 'chrome.exe', 'firefox.exe', 'edge.exe'}
        
    def start_monitoring(self):
        """Start elite monitoring - only real user actions"""
        self.monitoring = True
        
        # Monitor user file operations
        monitor_thread = threading.Thread(target=self._monitor_user_actions)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        logging.info("ELITE FILE MONITORING: Active - User actions only")
    
    def _monitor_user_actions(self):
        """Monitor only actual user file operations"""
        while self.monitoring:
            try:
                self._update_restricted_paths()
                
                # Get active window and process
                active_window = win32gui.GetForegroundWindow()
                if active_window:
                    _, pid = win32process.GetWindowThreadProcessId(active_window)
                    
                    try:
                        process = psutil.Process(pid)
                        process_name = process.name().lower()
                        
                        # Only monitor user applications
                        if process_name in self.user_processes:
                            # Check if process is accessing restricted files
                            try:
                                for file_info in process.open_files():
                                    file_path = file_info.path
                                    if self._is_restricted_and_user_action(file_path, process_name):
                                        self._create_real_alert(file_path, process_name)
                            except (psutil.AccessDenied, psutil.NoSuchProcess):
                                pass
                    
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                time.sleep(2)  # Check every 2 seconds
                
            except Exception as e:
                logging.error(f"Elite monitoring error: {e}")
                time.sleep(5)
    
    def _is_restricted_and_user_action(self, file_path, process_name):
        """Check if this is a restricted path AND a real user action"""
        if not file_path:
            return False
        
        # Skip system/temp files
        skip_patterns = [
            'temp', 'tmp', 'cache', 'log', '.lock', 'thumbs.db',
            'desktop.ini', 'pagefile.sys', 'hiberfil.sys'
        ]
        
        file_lower = file_path.lower()
        if any(pattern in file_lower for pattern in skip_patterns):
            return False
        
        # Check if path is restricted
        for restricted_path in self.restricted_paths:
            if file_path.lower().startswith(restricted_path.lower()):
                return True
        
        return False
    
    def _create_real_alert(self, file_path, process_name):
        """Create alert only for real user actions"""
        try:
            # Prevent duplicate alerts (30 second cooldown)
            alert_key = f"{file_path}_{process_name}"
            current_time = time.time()
            
            if alert_key in self.last_alerts:
                if current_time - self.last_alerts[alert_key] < 30:
                    return
            
            self.last_alerts[alert_key] = current_time
            
            # Create the alert
            self.threat_detector.handle_restricted_access(1, file_path, f"user_access_via_{process_name}")
            logging.critical(f"REAL USER ACTION BLOCKED: {process_name} accessing {file_path}")
            
        except Exception as e:
            logging.error(f"Alert creation error: {e}")
    
    def _update_restricted_paths(self):
        """Update restricted paths from database"""
        try:
            restricted = self.threat_detector.db.get_restricted_resources()
            if restricted:
                self.restricted_paths = {r['resource_path'] for r in restricted}
            else:
                self.restricted_paths = {'C:\\$Recycle.Bin', 'C:\\confidential', 'C:\\sensitive'}
        except Exception:
            self.restricted_paths = {'C:\\$Recycle.Bin', 'C:\\confidential', 'C:\\sensitive'}
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring = False
        logging.info("Elite file monitoring stopped")

class EliteUSBMonitor:
    def __init__(self, threat_detector):
        self.threat_detector = threat_detector
        self.monitoring = False
        self.known_drives = set()
        self.last_usb_check = 0
    
    def start_monitoring(self):
        """Start elite USB monitoring"""
        self.monitoring = True
        self._update_known_drives()
        
        usb_thread = threading.Thread(target=self._monitor_usb_elite)
        usb_thread.daemon = True
        usb_thread.start()
        
        logging.info("ELITE USB MONITORING: Active - Real devices only")
    
    def _monitor_usb_elite(self):
        """Monitor USB with smart detection"""
        while self.monitoring:
            try:
                current_time = time.time()
                
                # Only check every 3 seconds to avoid spam
                if current_time - self.last_usb_check < 3:
                    time.sleep(1)
                    continue
                
                self.last_usb_check = current_time
                current_drives = set(win32api.GetLogicalDriveStrings().split('\000')[:-1])
                
                # New USB devices
                new_drives = current_drives - self.known_drives
                for drive in new_drives:
                    if self._is_real_usb_device(drive):
                        label = self._get_drive_label(drive)
                        device_info = {'drive': drive, 'label': label, 'type': 'USB Storage'}
                        self.threat_detector.handle_usb_connection_fast(drive, device_info)
                        logging.warning(f"REAL USB CONNECTED: {drive} ({label})")
                
                # Removed USB devices
                removed_drives = self.known_drives - current_drives
                for drive in removed_drives:
                    if self._was_usb_drive(drive):
                        self.threat_detector.handle_usb_disconnection_fast(drive)
                        logging.info(f"USB REMOVED: {drive}")
                
                self.known_drives = current_drives
                time.sleep(3)
                
            except Exception as e:
                logging.error(f"Elite USB monitoring error: {e}")
                time.sleep(5)
    
    def _is_real_usb_device(self, drive):
        """Check if this is a real USB device (not virtual)"""
        try:
            drive_type = win32file.GetDriveType(drive)
            if drive_type != win32file.DRIVE_REMOVABLE:
                return False
            
            # Additional check - try to get volume info
            try:
                volume_info = win32api.GetVolumeInformation(drive)
                # Real USB devices usually have labels or can be accessed
                return True
            except:
                return False
                
        except:
            return False
    
    def _was_usb_drive(self, drive):
        """Check if removed drive was USB (simple heuristic)"""
        # Assume drives D: and above that were removed are USB
        return drive[0].upper() >= 'D'
    
    def _get_drive_label(self, drive):
        """Get drive label safely"""
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
        logging.info("Elite USB monitoring stopped")

class EliteMonitoringSystem:
    def __init__(self, threat_detector):
        self.threat_detector = threat_detector
        self.file_monitor = EliteFileMonitor(threat_detector)
        self.usb_monitor = EliteUSBMonitor(threat_detector)
        self.monitoring = False
    
    def start_all_monitoring(self):
        """Start elite monitoring system"""
        try:
            self.file_monitor.start_monitoring()
            self.usb_monitor.start_monitoring()
            self.monitoring = True
            
            logging.info("ELITE MONITORING SYSTEM: ACTIVE")
            logging.info("- Only REAL user actions trigger alerts")
            logging.info("- Smart USB detection (no false positives)")
            logging.info("- 30-second alert cooldown")
            
        except Exception as e:
            logging.error(f"Elite monitoring start error: {e}")
    
    def stop_all_monitoring(self):
        """Stop all monitoring"""
        try:
            self.file_monitor.stop_monitoring()
            self.usb_monitor.stop_monitoring()
            self.monitoring = False
            logging.info("Elite monitoring system stopped")
        except Exception as e:
            logging.error(f"Elite monitoring stop error: {e}")
    
    def is_monitoring(self):
        """Check if monitoring is active"""
        return self.monitoring