const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000;

// Middleware
app.use(cors());
app.use(express.json());

// MySQL Database Connection - First connect without database
const dbConnection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'samarth@2904'
});

// Create database if not exists
dbConnection.query('CREATE DATABASE IF NOT EXISTS cyber_defense_db', (err) => {
    if (err) {
        console.error('Error creating database:', err);
    } else {
        console.log('✅ Database cyber_defense_db ready');
    }
    dbConnection.end();
});

// Now connect to the specific database
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'samarth@2904',
    database: 'cyber_defense_db'
});

// Connect to database
db.connect((err) => {
    if (err) {
        console.error('Database connection failed:', err);
        return;
    }
    console.log('✅ Connected to MySQL database');
});

// Drop and recreate users table to ensure correct structure
db.query('DROP TABLE IF EXISTS users', (err) => {
    if (err) {
        console.error('Error dropping users table:', err);
    }
    
    const createUsersTable = `
        CREATE TABLE users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )
    `;
    
    db.query(createUsersTable, (err) => {
        if (err) {
            console.error('Error creating users table:', err);
        } else {
            console.log('✅ Users table created successfully');
        }
    });
});

// Register endpoint
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        // Check if user already exists
        const checkUser = 'SELECT * FROM users WHERE email = ?';
        db.query(checkUser, [email], async (err, results) => {
            if (err) {
                return res.status(500).json({ success: false, message: 'Database error' });
            }

            if (results.length > 0) {
                return res.status(400).json({ success: false, message: 'User already exists' });
            }

            // Validate password exists
            if (!password || password.length < 6) {
                return res.status(400).json({ success: false, message: 'Password must be at least 6 characters' });
            }
            
            // Hash password
            const hashedPassword = await bcrypt.hash(password, 10);

            // Insert new user
            const insertUser = 'INSERT INTO users (name, email, password) VALUES (?, ?, ?)';
            db.query(insertUser, [name, email, hashedPassword], (err, result) => {
                if (err) {
                    console.error('Database insert error:', err);
                    return res.status(500).json({ success: false, message: 'Failed to create user: ' + err.message });
                }

                res.status(201).json({ 
                    success: true, 
                    message: 'User created successfully',
                    userId: result.insertId 
                });
            });
        });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Login endpoint
app.post('/api/login', (req, res) => {
    try {
        const { email, password } = req.body;

        // Find user by email
        const findUser = 'SELECT * FROM users WHERE email = ?';
        db.query(findUser, [email], async (err, results) => {
            if (err) {
                return res.status(500).json({ success: false, message: 'Database error' });
            }

            if (results.length === 0) {
                return res.status(401).json({ success: false, message: 'Invalid email or password' });
            }

            const user = results[0];

            // Check password
            if (!password || !user.password) {
                return res.status(401).json({ success: false, message: 'Invalid email or password' });
            }
            
            const isValidPassword = await bcrypt.compare(password, user.password);
            if (!isValidPassword) {
                return res.status(401).json({ success: false, message: 'Invalid email or password' });
            }

            // Generate JWT token
            const token = jwt.sign(
                { userId: user.id, email: user.email },
                'cyber-defense-secret-key-2024',
                { expiresIn: '24h' }
            );

            res.json({
                success: true,
                message: 'Login successful',
                user: {
                    id: user.id,
                    name: user.name,
                    email: user.email
                },
                token
            });
        });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
});