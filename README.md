# AI-Based Threat Detection System

A web-based AI-powered threat detection system that integrates PE header analysis for `.exe` files, URL threat checks, file hash lookups, and extension verification. Designed for fast, reliable detection to support cybersecurity analysis and threat mitigation.

---

## 🚀 Features

- **PE Header-Based `.exe` File Analysis**  
  Detects malicious Windows executable files using a machine learning model (Random Forest) trained on PE header features.

- **URL Safety Checker**  
  Analyzes URLs for phishing, malware, or suspicious behavior using the VirusTotal API.

- **File Hash Analysis**  
  Checks file hashes against known malware databases (like VirusTotal).

- **File Extension Verification**  
  Identifies spoofed or mismatched file extensions to catch hidden threats.

---

## 🛠️ Tech Stack

- **Frontend:** HTML, CSS, JavaScript  
- **Backend:** Python, Flask  
- **Machine Learning:** scikit-learn (Random Forest)  
- **Libraries/Tools:** PEfile, hashlib, requests, pandas

---

## 📦 How to Run

1. **Clone the repository:**
   ```sh
   git clone https://github.com/pathik5/AI-Based-Threat-Detection-System.git
   cd AI-Based-Threat-Detection-System
   ```

2. **Install dependencies:**
   ```sh
   pip install -r requirements.txt
   ```

3. **Make sure `MalwareDataSet.csv` is present in the project directory.**

4. **Set your VirusTotal API key (if needed):**
   - Edit the configuration or set as an environment variable if required by your code.

5. **Run the application:**
   ```sh
   python app.py
   ```
   The app will be available at [http://localhost:5000](http://localhost:5000).

---

## 📁 Project Structure

```
AI-Based-Threat-Detection-System/
│
├── app.py                  # Main Flask application
├── MalwareDataSet.csv      # Dataset for training the ML model
├── static/                 # Static files (images, CSS, JS)
├── templates/              # HTML templates
├── requirements.txt
├── README.md
└── .gitignore
```

---

## ℹ️ Important Notes

- The AI model is trained on startup using `MalwareDataSet.csv`.  
- For URL and hash analysis, a valid VirusTotal API key is required.
- This project is for educational and research purposes only. Do not use it for malicious activities or in production environments.

---

## 📝 License

This project is open-source and available under the [MIT License](LICENSE).

---

## 🙋‍♂️ Author

- **GitHub:** [pathik5](https://github.com/pathik5)

---

## 🌐 GitHub Pages

A static project landing page is available at:  
[https://pathik5.github.io/AI-Based-Threat-Detection-System/](https://pathik5.github.io/AI-Based-Threat-Detection-System/)

> **Note:**  
> This page is for informational/demo purposes only. The full application (with all features) runs locally using Python/Flask.

---
