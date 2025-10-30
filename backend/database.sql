-- Create database
CREATE DATABASE IF NOT EXISTS cyber_defense_db;
USE cyber_defense_db;

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Create index on email for faster lookups
CREATE INDEX idx_email ON users(email);

-- Insert sample user (password: Test123!)
INSERT INTO users (name, email, password) VALUES 
('Test User', 'test@gmail.com', '$2b$10$rQZ8kHWKtGY5uY5uY5uY5uOQZ8kHWKtGY5uY5uY5uY5uOQZ8kHWKtG');

-- Show table structure
DESCRIBE users;