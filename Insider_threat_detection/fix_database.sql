-- Fix database column size issues
ALTER TABLE activity_logs MODIFY COLUMN event_type VARCHAR(50);
ALTER TABLE alerts MODIFY COLUMN alert_type VARCHAR(50);

-- Clear existing problematic data
DELETE FROM activity_logs;
DELETE FROM alerts;

-- Reset auto increment
ALTER TABLE alerts AUTO_INCREMENT = 1;
ALTER TABLE activity_logs AUTO_INCREMENT = 1;