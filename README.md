A professional network packet capture and analysis tool built with Qt6 and C++. Features a beautiful Apple-inspired dark theme UI for real-time network monitoring.

## ✨ Features

- 🔥 **Real-time Packet Capture** - Live network traffic monitoring
- 🌐 **Network Scanner** - Discover active devices on your network  
- 📤 **Packet Sender** - Send test packets to any IP:port
- 💾 **Export Functionality** - Save captured packets to JSON/TXT
- 🎨 **Modern UI** - Apple-style dark theme interface
- ⚡ **Multi-threaded** - Non-blocking capture and scanning

## 🖥️ Screenshots

Beautiful dark theme with real-time packet display:
- Network interface selection
- Live packet table with protocol detection
- Detailed packet inspection
- Network device discovery

## 🛠️ Requirements

- Qt6 (Core, Widgets)
- CMake 3.16+
- libpcap (Linux/macOS) or Npcap (Windows)
- C++17 compiler
- Root/Administrator privileges (for packet capture)

## 📦 Installation

### Linux/WSL:
```bash
# Install dependencies
sudo apt update
sudo apt install qt6-base-dev qt6-tools-dev cmake build-essential libpcap-dev

# Clone and build
git clone https://github.com/YOUR_USERNAME/PacketAnalyzer.git
cd PacketAnalyzer
cmake -B build -S .
cmake --build build

# Run (requires root for packet capture)
sudo ./build/PacketAnalyzer

[200~Windows:
bash# Install Qt6, CMake, and Npcap from their websites
# Then:
cmake -B build -S . -DCMAKE_PREFIX_PATH="C:\Qt\6.5.0\mingw_64"
cmake --build build
# Run as Administrator
🚀 Usage

Select Network Interface - Choose your WiFi/Ethernet adapter
Start Capture - Begin monitoring network traffic
Scan Network - Discover devices on your subnet
Send Packets - Test connectivity to any IP:port
Export Data - Save captured packets for analysis

⚠️ Security Notice
This tool requires administrator/root privileges for:

Raw packet capture access
Network interface monitoring
Packet injection capabilities

Use responsibly and only on networks you own or have permission to monitor.
🔧 Supported Protocols

TCP, UDP, ICMP
IPv4 traffic analysis
Ethernet frame parsing
Port-based application detection

📄 License
MIT License - Feel free to use and modify!
🤝 Contributing
Pull requests welcome! Please read contributing guidelines first.

Built with ❤️ using Qt6 and libpcap
