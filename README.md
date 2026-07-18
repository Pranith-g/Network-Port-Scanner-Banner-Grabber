# 🚀 Network Port Scanner & Banner Grabber

A professional **Python-based Network Port Scanner & Banner Grabber** built with **Streamlit**. The application enables users to scan hosts for open TCP ports, identify running services through banner grabbing, and maintain a persistent scan history using SQLite.

---

## 📌 Features

- 🔐 User Registration & Login Authentication
- 🌐 Multi-threaded TCP Port Scanning
- 📡 Banner Grabbing for Service Detection
- 📊 Interactive Dashboard
- 💾 SQLite Database for Persistent Scan History
- 🌙 Light/Dark Theme Support
- ⚡ Fast and Responsive Streamlit Interface
- 📈 Scan Results with Port Status and Service Information

---

## 🛠️ Tech Stack

- **Language:** Python 3.x
- **Framework:** Streamlit
- **Database:** SQLite
- **Networking:** Python Socket Library
- **Concurrency:** ThreadPoolExecutor (Multithreading)

---

## 📂 Project Structure

```
Network-Port-Scanner-Banner-Grabber/
│
├── app.py                 # Main Streamlit application
├── scanner.py             # Port scanning and banner grabbing logic
├── database.py            # SQLite database operations
├── utils.py               # Helper functions
├── requirements.txt       # Project dependencies
├── README.md              # Documentation
└── scanner_app.db         # SQLite database
```

---

## 🚀 Installation

### Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/Network-Port-Scanner-Banner-Grabber.git

cd Network-Port-Scanner-Banner-Grabber
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Run the Application

```bash
streamlit run app.py
```

---

## 📖 How to Use

1. Register a new account.
2. Log in to the application.
3. Enter the target IP address or domain.
4. Specify the port range.
5. Start the scan.
6. View:
   - Open Ports
   - Service Banners
   - Scan history

---

## 🎯 Key Functionalities

- Detect open TCP ports
- Perform banner grabbing
- Store scan history
- User authentication
- Dashboard interface
- Fast multi-threaded scanning


---

## ⚠️ Disclaimer

This project is intended **for educational purposes and authorized security testing only**. Do not use it against systems without proper permission.

---

## 👨‍💻 Author

**Pranith G**

GitHub: https://github.com/Pranith-g

