import win32api
import win32con
from plyer import notification
import logging

class SystemNotifications:
    @staticmethod
    def show_usb_alert(drive_path, device_label="Unknown Device"):
        """Show system notification for USB connection"""
        try:
            notification.notify(
                title="🚨 SECURITY ALERT - USB Device Detected",
                message=f"Unauthorized USB device connected: {device_label} ({drive_path})\nPlease remove immediately!",
                timeout=10,
                toast=True
            )
            
            # Also show Windows message box for critical alert
            win32api.MessageBox(
                0, 
                f"SECURITY ALERT!\n\nUnauthorized USB device detected:\n{device_label} at {drive_path}\n\nPlease remove the device immediately for security compliance.",
                "Insider Threat Detection System", 
                win32con.MB_ICONWARNING | win32con.MB_TOPMOST
            )
            
            logging.warning(f"USB notification shown for {drive_path}")
            
        except Exception as e:
            logging.error(f"Notification error: {e}")
    
    @staticmethod
    def show_file_restriction_alert(file_path, action="access"):
        """Show system notification for restricted file access"""
        try:
            notification.notify(
                title="🔒 ACCESS DENIED - Restricted File",
                message=f"Attempted {action} to restricted file:\n{file_path}\nAccess has been blocked!",
                timeout=8,
                toast=True
            )
            
            win32api.MessageBox(
                0,
                f"ACCESS DENIED!\n\nAttempted {action} to restricted file:\n{file_path}\n\nThis action has been blocked and logged for security review.",
                "File Access Control",
                win32con.MB_ICONERROR | win32con.MB_TOPMOST
            )
            
            logging.warning(f"File restriction notification shown for {file_path}")
            
        except Exception as e:
            logging.error(f"File notification error: {e}")
    
    @staticmethod
    def show_network_alert(bytes_transferred, interface):
        """Show notification for suspicious network activity"""
        try:
            mb_size = bytes_transferred / (1024 * 1024)
            notification.notify(
                title="🌐 NETWORK ALERT - Large Data Transfer",
                message=f"Suspicious data transfer detected:\n{mb_size:.1f}MB on {interface}",
                timeout=6,
                toast=True
            )
            
        except Exception as e:
            logging.error(f"Network notification error: {e}")