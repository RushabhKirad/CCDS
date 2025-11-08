import win32api
import win32file
import win32con
import wmi
import threading
import time
import logging
from datetime import datetime

class DeviceMonitor:
    def __init__(self, threat_detector):
        self.threat_detector = threat_detector
        self.known_devices = set()
        self.monitoring = False
        self.wmi = wmi.WMI()
        self.setup_logging()
        
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - [Device Monitor] %(message)s',
            handlers=[
                logging.FileHandler('logs/device_monitor.log'),
                logging.StreamHandler()
            ]
        )
        
    def start_monitoring(self):
        """Start device monitoring in a separate thread"""
        try:
            self.monitoring = True
            self.update_known_devices()  # Initial device scan
            
            # Start the monitoring thread
            monitor_thread = threading.Thread(
                target=self._monitor_devices,
                name="DeviceMonitorThread",
                daemon=True
            )
            monitor_thread.start()
            logging.info("Device monitoring started successfully")
            
        except Exception as e:
            logging.error(f"Failed to start device monitoring: {e}")
            
    def stop_monitoring(self):
        """Stop device monitoring"""
        self.monitoring = False
        logging.info("Device monitoring stopped")
        
    def update_known_devices(self):
        """Update the list of known devices"""
        try:
            # Get all USB devices
            self.known_devices = set(self._get_all_device_ids())
            logging.debug(f"Updated known devices: {len(self.known_devices)} devices found")
        except Exception as e:
            logging.error(f"Error updating known devices: {e}")
            
    def _get_all_device_ids(self):
        """Get all current device IDs"""
        device_ids = set()
        
        try:
            # Check USB storage devices
            for disk in self.wmi.Win32_DiskDrive():
                if disk.InterfaceType == "USB" or "Portable" in disk.Caption:
                    device_ids.add(disk.PNPDeviceID)
                    
            # Check USB hubs and controllers
            for hub in self.wmi.Win32_USBHub():
                device_ids.add(hub.PNPDeviceID)
                
            # Check mobile devices (MTP)
            for device in self.wmi.Win32_PnPEntity():
                if "USB" in device.Name or "Portable" in device.Name:
                    device_ids.add(device.PNPDeviceID)
                    
        except Exception as e:
            logging.error(f"Error getting device IDs: {e}")
            
        return device_ids
        
    def _monitor_devices(self):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                current_devices = set(self._get_all_device_ids())
                
                # Check for new devices
                new_devices = current_devices - self.known_devices
                for device_id in new_devices:
                    self._handle_new_device(device_id)
                    
                # Check for removed devices
                removed_devices = self.known_devices - current_devices
                for device_id in removed_devices:
                    self._handle_removed_device(device_id)
                    
                # Update known devices
                self.known_devices = current_devices
                
                # Sleep for a short interval
                time.sleep(1)
                
            except Exception as e:
                logging.error(f"Error in device monitoring loop: {e}")
                time.sleep(5)
                
    def _handle_new_device(self, device_id):
        """Handle new device connection"""
        try:
            device_info = self._get_device_info(device_id)
            if device_info:
                logging.info(f"New device detected: {device_info['name']}")
                self.threat_detector.handle_usb_connection(
                    drive_path=device_info.get('drive_letter', 'Unknown'),
                    device_info=device_info
                )
        except Exception as e:
            logging.error(f"Error handling new device: {e}")
            
    def _handle_removed_device(self, device_id):
        """Handle device removal"""
        try:
            device_info = {'id': device_id}  # Basic info for removed device
            logging.info(f"Device removed: {device_id}")
            self.threat_detector.handle_usb_disconnection(
                drive_path="Unknown",
                device_info=device_info
            )
        except Exception as e:
            logging.error(f"Error handling removed device: {e}")
            
    def _get_device_info(self, device_id):
        """Get detailed device information"""
        try:
            # Query WMI for device details
            for device in self.wmi.Win32_PnPEntity():
                if device.PNPDeviceID == device_id:
                    info = {
                        'id': device_id,
                        'name': device.Name,
                        'description': device.Description,
                        'manufacturer': device.Manufacturer,
                        'class': device.ClassGuid,
                        'status': device.Status,
                        'timestamp': datetime.now().isoformat(),
                        'type': 'Unknown'
                    }
                    
                    # Determine device type
                    if "USB" in device.Name:
                        info['type'] = 'USB Device'
                    elif "Portable" in device.Name:
                        info['type'] = 'Mobile Device'
                        
                    # Get drive letter for storage devices
                    if "Mass Storage" in device.Name:
                        info['drive_letter'] = self._get_drive_letter(device_id)
                        
                    return info
            return None
        except Exception as e:
            logging.error(f"Error getting device info: {e}")
            return None
            
    def _get_drive_letter(self, device_id):
        """Get drive letter for storage device"""
        try:
            for disk in self.wmi.Win32_DiskDrive():
                if disk.PNPDeviceID == device_id:
                    for partition in disk.associators("Win32_DiskDriveToDiskPartition"):
                        for logical_disk in partition.associators("Win32_LogicalDiskToPartition"):
                            return logical_disk.DeviceID
            return None
        except Exception as e:
            logging.error(f"Error getting drive letter: {e}")
            return None
            
    def get_connected_devices(self):
        """Get list of currently connected devices"""
        devices = []
        try:
            for device_id in self.known_devices:
                device_info = self._get_device_info(device_id)
                if device_info:
                    devices.append(device_info)
        except Exception as e:
            logging.error(f"Error getting connected devices: {e}")
        return devices