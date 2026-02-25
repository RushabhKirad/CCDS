import os
import time
import threading
import psutil
import win32gui
import win32process
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class UserFileAccessHandler(FileSystemEventHandler):
    def __init__(self, threat_detector):
        self.threat_detector = threat_detector
        self.last_alerts = {}
    
    def on_opened(self, event):
        """Only trigger when user opens files/folders"""
        if self._is_user_action(event.src_path):
            self._check_and_alert(event.src_path, 'opened')
    
    def _is_user_action(self, file_path):
        """Check if this is a real user action"""
        try:
            # Get the active window process
            active_window = win32gui.GetForegroundWindow()
            if active_window:
                _, pid = win32process.GetWindowThreadProcessId(active_window)
                process = psutil.Process(pid)
                process_name = process.name().lower()
                
                # Only consider user applications
                user_apps = ['explorer.exe', 'notepad.exe', 'chrome.exe', 'firefox.exe']
                return process_name in user_apps
        except:
            pass
        return False
    
    def _check_and_alert(self, file_path, action):
        """Check if path is restricted and create alert"""
        try:
            # Get restricted paths from database
            restricted_paths = self.threat_detector.get_restricted_paths()
            
            # Check if file path matches any restricted path
            for restricted_path in restricted_paths:
                if file_path.lower().startswith(restricted_path.lower()):
                    # Prevent duplicate alerts (10 second cooldown)
                    alert_key = f"{file_path}_{action}"
                    current_time = time.time()
                    
                    if alert_key in self.last_alerts:
                        if current_time - self.last_alerts[alert_key] < 10:
                            return
                    
                    self.last_alerts[alert_key] = current_time
                    
                    # Create alert
                    self.threat_detector.handle_restricted_access(1, file_path, f'user_{action}')
                    logging.warning(f"USER OPENED RESTRICTED: {file_path}")
                    break
                    
        except Exception as e:
            logging.error(f"Alert check error: {e}")

class SimpleMonitor:
    def __init__(self, threat_detector):
        self.threat_detector = threat_detector
        self.observer = Observer()
        self.handler = UserFileAccessHandler(threat_detector)
        self.monitoring = False
    
    def start_monitoring(self):
        """Start monitoring user file access"""
        try:
            # Monitor key directories where restricted files might be
            monitor_paths = ['C:\\', 'D:\\', 'E:\\']
            
            for path in monitor_paths:
                if os.path.exists(path):
                    self.observer.schedule(self.handler, path, recursive=True)
            
            self.observer.start()
            self.monitoring = True
            logging.info("Simple monitoring started - User file access only")
            
        except Exception as e:
            logging.error(f"Monitoring start error: {e}")
    
    def stop_monitoring(self):
        """Stop monitoring"""
        try:
            self.observer.stop()
            self.observer.join()
            self.monitoring = False
            logging.info("Simple monitoring stopped")
        except Exception as e:
            logging.error(f"Monitoring stop error: {e}")
    
    def is_monitoring(self):
        return self.monitoring