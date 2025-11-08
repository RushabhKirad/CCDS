# Cognitive Cyber Defense System

A comprehensive cybersecurity system that utilizes AI and machine learning to provide real-time threat detection and response. The system consists of three main modules working together to provide holistic security coverage.

## Features

### 1. Real-Time Traffic Anomaly Detection
- Advanced network traffic monitoring
- ML-based anomaly detection
- Real-time threat alerts
- Traffic pattern analysis
- Automated response capabilities

### 2. Advanced Email Security & Phishing Detection
- AI-powered email analysis with 5 ML models
- 99.8% accuracy in threat detection
- Post-quantum cryptography implementation
- Real-time Gmail integration
- Comprehensive email threat detection

### 3. Insider Threat Detection & Behavioral Analysis
- LSTM-based behavioral learning
- USB and mobile device monitoring
- File access monitoring
- User behavior pattern analysis
- Real-time alerts for suspicious activities

## System Architecture

The system is built with a microservices architecture, with each module running independently:

- Backend API: Port 3000
- Email Security System: Port 5000
- Insider Threat Detection: Port 5002
- Anomaly Detection System: Port 8001
- Frontend: Served via HTTP server

## Technologies Used

- Python (Machine Learning & Backend)
- Node.js (Backend API)
- HTML/CSS/JavaScript (Frontend)
- MySQL Database
- TensorFlow/PyTorch
- Flask/Express.js

## Setup Instructions

1. Install dependencies:
   ```bash
   # Backend
   cd backend
   npm install

   # Email Security System
   cd EMAIL_SECURITY_SYSTEM_2
   pip install -r requirements.txt

   # Insider Threat Detection
   cd Insider_threat_detection
   pip install -r requirements.txt

   # Anomaly Detection
   cd nitedu-anomaly-detection
   pip install -r requirements.txt
   ```

2. Configure MySQL database with provided credentials

3. Start the services:
   - Run backend: `npm start`
   - Run email security: `python app.py`
   - Run insider threat: `python app.py`
   - Run anomaly detection: `python run.py`

## Development Team

- **Samyak Bhongade** - Anomaly Detection System
- **Rushabh Kirad** - Email Security System
- **Riddhi Sathe** - Insider Threat Detection

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

Special thanks to our mentors and the open-source community for their invaluable contributions and support.

## Contact

For any queries or support:
- [Samyak's LinkedIn](https://www.linkedin.com/in/samyakbhongade/)
- [Rushabh's LinkedIn](https://www.linkedin.com/in/rushabh-kirad)
- [Riddhi's LinkedIn](https://www.linkedin.com/in/riddhi-sathe)

## Project Status

🚀 Active Development