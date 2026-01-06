# 🔐 Password Cracker (Educational & Pentesting Tool)

## 📌 Overview
This project is a **password cracking tool** designed strictly for **educational purposes and authorized penetration testing**.  
It demonstrates how weak passwords can be identified using **dictionary-based attacks** against hashed passwords.

The goal is to help learners understand:
- Why weak passwords are dangerous
- How attackers exploit poor password hygiene
- How defenders can improve security controls

---

## ⚙️ Features
- Dictionary-based password cracking
- Supports hashed passwords
- Multi-threaded execution for speed
- Built with **C++** and **OpenSSL**
- Easy to extend with more hash algorithms

---

## 🛠️ Supported Hash Algorithms
- MD5  
- SHA-1  
- SHA-256  

---

## 📂 Project Structure
```
password_cracker/
│
├── password_cracker.cpp   # Main source code
├── hashes.txt             # Target hashes (one per line)
├── dictionary.txt         # Wordlist
└── README.md              # Project documentation
```

---

## 🚀 How It Works
1. Loads hashed passwords from `hashes.txt`
2. Reads possible passwords from `dictionary.txt`
3. Hashes each dictionary word using the chosen algorithm
4. Compares generated hashes with target hashes
5. Displays any successfully cracked passwords

---

## ▶️ Compilation
Ensure OpenSSL is installed, then compile using:

```bash
g++ -o password_cracker password_cracker.cpp -lssl -lcrypto -std=c++11 -pthread
```

---

## ▶️ Usage
```bash
./password_cracker
```

Requirements:
- `hashes.txt`: one hash per line
- `dictionary.txt`: list of possible passwords

---

## 📖 Example Use Cases
- Cybersecurity learning labs
- Ethical hacking practice
- Password strength testing
- CTF challenges
- Security awareness demonstrations

---

## ⚠️ Legal & Ethical Disclaimer
🚨 **IMPORTANT NOTICE**

This tool is intended **ONLY** for:
- Systems you own
- Systems you have **explicit permission** to test
- Educational labs and simulations

Unauthorized use against real systems, accounts, or networks is **illegal** and unethical.

The author takes **no responsibility** for misuse of this software.

---

## 🔒 Security Insight
Weak passwords remain one of the most common attack vectors.  
This project highlights the importance of:
- Strong passwords
- Proper hashing algorithms
- Salting and multi-factor authentication (MFA)

---

## 🧩 Future Improvements
- Rule-based attacks
- Hybrid attacks
- Hash auto-detection
- GPU acceleration
- Password strength reporting

---

## 📜 License
This project is released for **educational and research purposes only**.
