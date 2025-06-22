# 🔍 PacketAnalyzer

> A sleek, nice network packet capture and analysis tool with real-time scanning capabilities

<div align="center">

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-green.svg)
![Qt](https://img.shields.io/badge/Qt-6.0+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-red.svg)

**[Features](#-features) • [Installation](#-installation)**

</div>

---
<img src="screenshots/Screenshot1" alt="Main Interface" width="80%">

## 🌟 Features

<table>
<tr>
<td width="50%">

### 📡 **Network Capture**
- ⚡ **Real-time packet monitoring** with libpcap
- 🔌 **Auto-detect network interfaces** (WiFi/Ethernet)
- 📊 **Live packet analysis** with protocol detection
- 💾 **Export capabilities** (JSON/TXT formats)

</td>
<td width="50%">

### 🌐 **Network Discovery** 
- 🗺️ **Fast nmap integration** for device scanning
- 🏷️ **MAC address detection** with vendor info
- 🎯 **Smart network range detection** (172.16.x.x support)
- 📋 **Clean, organized results** display

</td>
</tr>
</table>

---

## 🚀 Installation

### Prerequisites
```bash
# Ubuntu/Debian
sudo apt update && sudo apt install qt6-base-dev libqt6widgets6 libpcap-dev nmap

# Arch Linux
sudo pacman -S qt6-base libpcap nmap

# Fedora/RHEL
sudo dnf install qt6-qtbase-devel libpcap-devel nmap
```
### Quick Setup
```bash
git clone https://github.com/Nytso2/PacketAnalyzer.git
cd PacketAnalyzer
qmake6 && make
sudo ./PacketAnalyzer  # Root required for packet capture
```
## ⚙️ Network Configuration

**Most users won't need to edit anything** - the tool auto-detects your network. But if network scanning doesn't find devices, you may need to adjust these lines:

### 📍 Location: `main.cpp` around line 450-460

```cpp
// In the scanNetwork() function - edit if needed:

if (localIP.startsWith("172.16.")) {
    networkRange = "172.16.0.0/23";  // ← Change this number if needed
} else if (localIP.startsWith("192.168.")) {
    QStringList parts = localIP.split('.');
    networkRange = parts[0] + "." + parts[1] + "." + parts[2] + ".0/24";  // ← Usually fine
} else if (localIP.startsWith("10.")) {
    networkRange = "10.0.0.0/8";     // ← Change this number if needed
} else {
    // Fallback for other networks
    QStringList parts = localIP.split('.');
    networkRange = parts[0] + "." + parts[1] + "." + parts[2] + ".0/24";
}
```
🔍 How to Check Your Network:

```bash
ip route | grep default
```
### 📝 Only Edit If:

- Network scan finds 0 devices but you know there are devices You're on a corporate network with custom IP ranges Your router uses non-standard subnets

### Requirements

- Qt 6.0+ - Modern C++ GUI framework
- libpcap - Low-level packet capture
- nmap - Network discovery tool
- Linux/Windows - Cross-platform support
- Root/Admin - Required for packet capture

### License
- This project is licensed under the MIT License - see the LICENSE file for details.
### NOTICE
- This tool is designed for educational purposes and authorized network analysis only. Users must ensure compliance with all applicable laws and regulations. 
