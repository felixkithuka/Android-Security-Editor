# 🛡️ Android Security Editor

[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**Android Security Editor** is a powerful post-exploitation framework that uses ADB over TCP/IP to remotely access and control Android devices. It is designed for authorized security research, bug bounty hunting, and forensic analysis.

> **⚠️ Legal & Ethical Notice**  
> This tool is intended for **authorized security research, educational purposes, and testing your own devices**.  
> Unauthorized access to devices or networks is illegal. Always obtain written permission before testing any device you do not own.

---

## ✨ Features

### Device Discovery & Connection
- Connect to any Android device via ADB over TCP/IP (no USB required)
- Scan local subnets for devices with ADB port (5555) open
- **Automatic proxy discovery** with SOCKS5 support for IP masking
- **Proxy verification** – tests each proxy before use

### Data Extraction
- 📱 Dump contacts (name + number) to `.txt` file
- 💬 Extract SMS messages from inbox
- 📞 Retrieve call logs with timestamps and durations

### Application Management
- 📦 List all installed apps (with export option)
- ⬆️ Install APK files remotely
- ❌ Uninstall any package
- ▶️ Launch any app by package name

### File Operations
- 📥 Pull files from device to PC
- 📤 Push files from PC to device

### Media & Control
- 📸 Take screenshots (auto-saved locally)
- 🎥 Record screen with adjustable duration
- 🖥️ Interactive ADB shell for manual control

### Device Control
- 🔄 Reboot device
- ⚡ Power off device
- 📶 Toggle Wi-Fi on/off
- 📋 Pull full logcat dump

### Security Assessment
- 🔍 Root detection (test-keys, su binary)
- 📊 Comprehensive device info (model, Android version)

---

## 📋 Requirements

### Core Requirements (All Platforms)
- **Python 3.7+**
- **ADB (Android Debug Bridge)** – [Platform Tools](https://developer.android.com/studio/releases/platform-tools)

### Python Dependencies
bash
pip install PySocks colorama requests

### 
