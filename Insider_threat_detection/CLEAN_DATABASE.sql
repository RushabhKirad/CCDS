-- Clean Database Setup for Insider Threat Detection System
-- Run this first to clean existing database

DROP DATABASE IF EXISTS InsiderThreatDB;
CREATE DATABASE InsiderThreatDB;
USE InsiderThreatDB;

-- Organizations table (companies/departments)
CREATE TABLE organizations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    org_name VARCHAR(100) NOT NULL UNIQUE,
    org_code VARCHAR(20) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Users table (employees)
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    org_id INT NOT NULL,
    department VARCHAR(50),
    role ENUM('admin', 'manager', 'employee') DEFAULT 'employee',
    ip_address VARCHAR(45),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
);

-- User behavioral baselines (learned patterns)
CREATE TABLE user_baselines (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    avg_daily_file_access INT DEFAULT 0,
    avg_daily_network_activity BIGINT DEFAULT 0,
    typical_work_hours_start TIME DEFAULT '09:00:00',
    typical_work_hours_end TIME DEFAULT '17:00:00',
    common_file_types JSON,
    common_applications JSON,
    baseline_updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Activity logs (all user activities)
CREATE TABLE activity_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    timestamp DATETIME NOT NULL,
    event_type ENUM('file_access', 'file_modify', 'file_delete', 'usb_connect', 'usb_disconnect', 'login', 'logout', 'network_activity', 'process_start', 'failed_login') NOT NULL,
    file_path VARCHAR(500),
    process_name VARCHAR(255),
    network_destination VARCHAR(100),
    bytes_transferred BIGINT DEFAULT 0,
    device_info VARCHAR(255),
    outcome ENUM('success', 'blocked', 'failed') DEFAULT 'success',
    anomaly_score FLOAT DEFAULT 0.0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_timestamp (user_id, timestamp),
    INDEX idx_event_type (event_type),
    INDEX idx_anomaly_score (anomaly_score)
);

-- Restricted files/folders
CREATE TABLE restricted_resources (
    id INT AUTO_INCREMENT PRIMARY KEY,
    resource_path VARCHAR(500) NOT NULL,
    resource_type ENUM('file', 'folder', 'registry') DEFAULT 'file',
    restriction_level ENUM('read_only', 'no_access', 'admin_only') DEFAULT 'no_access',
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Alerts table
CREATE TABLE alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    alert_type ENUM('usb_connection', 'restricted_access', 'behavioral_anomaly', 'network_spike', 'failed_login_spike') NOT NULL,
    severity ENUM('low', 'medium', 'high', 'critical') NOT NULL,
    title VARCHAR(200) NOT NULL,
    description TEXT NOT NULL,
    metadata JSON,
    is_acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_by INT,
    acknowledged_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (acknowledged_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_severity (severity),
    INDEX idx_acknowledged (is_acknowledged),
    INDEX idx_created_at (created_at)
);

-- System configuration
CREATE TABLE system_config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    config_key VARCHAR(100) NOT NULL UNIQUE,
    config_value TEXT NOT NULL,
    description TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Insert default data
INSERT INTO organizations (org_name, org_code) VALUES 
('CyberSec Corp', 'CSC001'),
('Default Organization', 'DEF001');

INSERT INTO users (username, password_hash, full_name, email, org_id, role) VALUES 
('admin', 'pbkdf2:sha256:260000$salt$hash', 'System Administrator', 'admin@cybersec.com', 1, 'admin');
-- Password is 'admin123' - will be updated by setup script

INSERT INTO restricted_resources (resource_path, resource_type, restriction_level, description) VALUES 
('C:\\Windows\\System32\\config', 'folder', 'admin_only', 'Windows System Configuration'),
('C:\\confidential', 'folder', 'no_access', 'Confidential Documents'),
('C:\\sensitive', 'folder', 'admin_only', 'Sensitive Data'),
('*.key', 'file', 'no_access', 'Private Key Files'),
('*.pem', 'file', 'no_access', 'Certificate Files');

INSERT INTO system_config (config_key, config_value, description) VALUES 
('anomaly_threshold', '0.7', 'Threshold for anomaly detection'),
('learning_period_days', '7', 'Days to learn user behavior'),
('alert_retention_days', '90', 'Days to keep alerts'),
('max_failed_logins', '5', 'Maximum failed login attempts before alert');