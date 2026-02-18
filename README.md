# 🚀 Subdocker-V2
### Advanced Async Subdomain Enumeration & Attack Surface Mapping Framework  

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![AsyncIO](https://img.shields.io/badge/AsyncIO-Enabled-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![Maintained](https://img.shields.io/badge/Maintained-Yes-brightgreen)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey)
![Cybersecurity](https://img.shields.io/badge/Domain-Cybersecurity-red)

---

## 🧠 Overview

**Subdocker** is a high-performance, asynchronous subdomain reconnaissance tool designed for modern attack surface mapping and penetration testing.

Built using Python's `asyncio`, it enables fast passive enumeration, brute-force discovery, DNS resolution, HTTP probing, WAF detection, and optional Nmap scanning — all in one streamlined framework.

---

## ⚡ Features

✔ Passive Subdomain Enumeration  
✔ Brute-force Subdomain Discovery  
✔ Asynchronous DNS Resolution (aiodns)  
✔ HTTP/HTTPS Probing  
✔ Basic WAF Detection  
✔ Wildcard DNS Detection  
✔ JSON & Text Output Support  
✔ Optional Nmap Integration  
✔ Rate Limiting  
✔ Clean CLI Interface  

---

## 🏗 Architecture

```
Passive Sources  →  
Brute Engine     →  Async Event Loop  →  DNS Resolver  →  
HTTP Probe       →  WAF Detection     →  Output Engine  
```

Powered by:

- asyncio
- aiohttp
- aiodns
- Nmap (optional integration)

---

## 📦 Installation

### 🔹 Linux (Kali / Ubuntu)

```bash
sudo apt update
sudo apt install python3 python3-pip nmap -y

git clone https://github.com/yourusername/subdocker.git
cd subdocker

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

Run:

```bash
python3 subdocker.py -d example.com
```

---

### 🔹 Windows

1. Install Python (Add to PATH)
2. Install Nmap
3. Clone repo

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python subdocker.py -d example.com
```

---

## 🚀 Usage

### Basic Scan
```bash
python subdocker.py -d example.com
```

### With Wordlist
```bash
python subdocker.py -d example.com -w wordlist.txt
```

### Resolve IPs
```bash
python subdocker.py -d example.com --ip
```

### HTTP + WAF Detection
```bash
python subdocker.py -d example.com --http --waf
```

### Save Output
```bash
python subdocker.py -d example.com --json -o results.json
```

### With Nmap Scan
```bash
python subdocker.py -d example.com --ip --nmap
```

---

## 📊 Performance

| Mode           | Time Efficiency | Network Usage |
|----------------|-----------------|---------------|
| Passive        |      Very Fast  |      Low      |
| Brute Force    |        Medium   |    Medium     |
| HTTP Probe     |    Fast (Async) |    Medium     |
| Nmap           |     Slower      |      High     |
----------------------------------------------------

## 🛡 Use Cases

- Penetration Testing  
- Bug Bounty Recon  
- Attack Surface Mapping  
- Red Team Reconnaissance  
- Cybersecurity Research  

---

## 🔐 Legal Disclaimer

This tool is intended for **educational and authorized security testing only**.  
Do not use against targets without proper permission.

The developer is not responsible for misuse.

---

## 👨‍💻 Author

**Amithabh D.K**  
Cybersecurity Enthusiast | Offensive Security | Attack Surface Research  

---

## ⭐ Support

If you find this tool useful:

- ⭐ Star the repository  
- 🍴 Fork it  
- 🧠 Contribute improvements  

---

> "Recon is the foundation of every successful penetration test."
