# -Intrusion-Detection-System
Real-time Network Intrusion Detection System powered by Machine Learning with interactive dashboards and secure alert management.

# 🚨 AI-Powered Network Intrusion Detection System (NIDS)

An AI-powered Network Intrusion Detection System that leverages Machine Learning to identify malicious network traffic and provides real-time monitoring through an interactive web dashboard.

## 📌 Overview

This project combines Machine Learning, Backend APIs, and a Modern Web Dashboard to detect, classify, and visualize network attacks in real time.

### Key Features

- Real-time intrusion detection
- Machine Learning-based attack classification
- Interactive monitoring dashboard
- Live attack alerts using WebSockets
- Secure alert storage and verification
- Attack statistics and trend visualization
- REST API integration

---

## 🏗️ System Architecture

```text
Network Traffic
       │
       ▼
┌─────────────────┐
│   ML Engine     │
│    FastAPI      │
│ Random Forest   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Backend Server  │
│ Node.js Express │
│   Socket.IO     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ React Dashboard │
│ Real-Time UI    │
└─────────────────┘
```

---

## 🛠️ Tech Stack

### Machine Learning
- Python
- FastAPI
- Scikit-Learn
- Pandas
- NumPy
- Joblib

### Backend
- Node.js
- Express.js
- Socket.IO
- Axios
- CryptoJS

### Frontend
- React
- Vite
- Recharts
- Socket.IO Client

---

## 📂 Project Structure

```text
project-root/
│
├── backend/
│   ├── server.js
│   ├── package.json
│   └── package-lock.json
│
├── dashboard/
│   ├── src/
│   ├── public/
│   ├── package.json
│   └── vite.config.js
│
├── ml-engine/
│   ├── main.py
│   ├── requirements.txt
│   ├── random_forest_model.pkl
│   ├── label_encoder.pkl
│   └── feature_names.pkl
│
└── notebooks/
    ├── EDA.ipynb
    └── Model_Training.ipynb
```

---

## 🚀 Getting Started

### Prerequisites

Install the following:

- Node.js (v18 or higher)
- Python (v3.10 or higher)
- Git

---

## 1️⃣ Clone the Repository

```bash
git clone https://github.com/your-username/your-repository-name.git

cd your-repository-name
```

---

## 2️⃣ Setup the Machine Learning Engine

Navigate to the ML engine directory:

```bash
cd ml-engine
```

Create a virtual environment:

### Windows

```bash
python -m venv venv

venv\Scripts\activate
```

### Linux/Mac

```bash
python3 -m venv venv

source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Start the FastAPI server:

```bash
uvicorn main:app --reload
```

API Documentation:

```text
http://localhost:8000/docs
```

---

## 3️⃣ Setup the Backend Server

Open a new terminal:

```bash
cd backend
```

Install dependencies:

```bash
npm install
```

Start the backend server:

```bash
npm start
```

Backend URL:

```text
http://localhost:5000
```

---

## 4️⃣ Setup the Dashboard

Open another terminal:

```bash
cd dashboard
```

Install dependencies:

```bash
npm install
```

Run the dashboard:

```bash
npm run dev
```

Dashboard URL:

```text
http://localhost:5173
```

---

## 🔌 API Endpoints

### Health Check

```http
GET /
```

### Get Alerts

```http
GET /alerts
```

### Get Statistics

```http
GET /stats
```

### Clear Alerts

```http
DELETE /alerts
```

### Verify Alert

```http
POST /alerts/verify
```

### Decrypt Alert

```http
POST /alerts/decrypt
```

### Predict Attack

```http
POST /predict
```

---

## 📊 Dashboard Features

- Live intrusion monitoring
- Attack distribution charts
- Attack severity visualization
- Real-time alert updates
- Historical attack tracking
- Performance metrics

---

## 🤖 Machine Learning Model

The intrusion detection engine uses a trained Random Forest Classifier to:

- Detect malicious network activity
- Classify attack categories
- Generate confidence scores
- Determine attack severity levels

---

## 🔒 Security Features

- AES encryption for sensitive alerts
- SHA-256 hash verification
- Secure API communication
- Alert integrity validation

---

## 📈 Future Enhancements

- Docker deployment
- Kubernetes support
- Cloud deployment
- User authentication
- Email notifications
- SIEM integration
- Automated incident response

---

## 👨‍💻 Author

**Hemanth Bharadwaj NR**

Engineering Student | AI & Cybersecurity Enthusiast

---

## 📜 License

This project is developed for educational and research purposes.

Feel free to fork, improve, and contribute.

---

⭐ If you found this project useful, consider giving it a star.
