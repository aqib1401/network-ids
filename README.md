# Network Intrusion Detection System (NIDS)

A real-time network packet analyzer and intrusion detection system with a modern GUI interface. Built for cybersecurity analysis and network monitoring.

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![PyQt6](https://img.shields.io/badge/GUI-PyQt6-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## Features

### Real-Time Threat Detection
- **Port Scan Detection** - Identifies rapid connection attempts to multiple ports
- **SYN Flood Detection** - Detects half-open connection floods
- **ICMP Flood Detection** - Monitors excessive ping traffic
- **DNS Tunneling Detection** - Flags suspicious DNS queries (long/high-entropy)
- **ARP Spoofing Detection** - Monitors MAC address changes
- **Suspicious IP Detection** - Checks against configurable IP blacklist

### User Interface
- **Live Dashboard** - Real-time statistics and graphs
- **Packet Viewer** - Detailed packet inspection table
- **Threat Log** - Color-coded security alerts
- **Report Generator** - Professional HTML/CSV/JSON reports
- **Configurable Settings** - Adjustable detection thresholds

### Technical Highlights
- Multithreaded packet capture (non-blocking GUI)
- Asynchronous packet processing with Scapy
- Real-time data visualization with Matplotlib
- Modular architecture for easy extension

## Installation

### Prerequisites
- Python 3.10 or higher
- Windows: [Npcap](https://npcap.com/) (required for packet capture)
  - During installation, check "Install Npcap in WinPcap API-compatible mode"
- Linux/Mac: libpcap

### Setup
```bash
# Clone the repository
git clone https://github.com/aqib1401/network-ids.git
cd network-ids

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Running the Application
```bash
# Windows (run as Administrator)
python main.py

# Linux/Mac (run with sudo)
sudo python main.py
```

### Quick Start
1. Launch the application
2. Go to **Settings** tab and select your network interface
3. Click **Start Capture** in the toolbar
4. Monitor the **Dashboard** for traffic statistics
5. Check **Threat Log** for security alerts
6. Generate reports from the **Report** tab

### Test Mode
Click **🧪 Inject Test Alerts** in the toolbar to inject sample threat alerts for demonstration purposes.

## Project Structure
```
network-ids/
├── gui/                    # PyQt6 GUI components
│   ├── main_window.py     # Main application window
│   ├── dashboard_tab.py   # Live statistics dashboard
│   ├── packet_viewer_tab.py
│   ├── threat_log_tab.py
│   ├── report_tab.py
│   └── settings_tab.py
├── core/                   # Backend logic
│   ├── capture.py         # Packet capture engine
│   ├── detector.py        # Threat detection algorithms
│   ├── analyzer.py        # Traffic analysis
│   ├── reporter.py        # Report generation
│   └── utils.py           # Utility functions
├── config/
│   └── config.yaml        # Configuration file
├── output/                # Generated reports and PCAPs
├── main.py                # Application entry point
└── requirements.txt       # Python dependencies
```

## Configuration

Edit `config/config.yaml` to customize detection thresholds:

```yaml
thresholds:
  syn_flood:
    max_syn_per_ip: 50
    time_window: 30
  port_scan:
    min_ports: 10
    time_window: 60
  icmp_flood:
    max_icmp_per_sec: 100

suspicious_ips:
  - "192.168.1.100"
  - "10.0.0.200"

dns_tunneling:
  max_query_length: 50
  high_entropy_threshold: 4.5
```

## Traffic Generation for Testing

### Real Network Traffic
```bash
# Windows
.\real_traffic_test.bat

# Linux/Mac
ping -c 10 8.8.8.8
nslookup google.com
```

### Threat Simulation
```bash
python threat_generator.py
```

## Screenshots

### Dashboard
Real-time traffic statistics with protocol distribution and packet rate graphs.

### Threat Log
Color-coded security alerts with timestamps and severity levels.

### Reports
Professional HTML reports with charts and detailed threat analysis.

## Technologies Used
- **Python 3.10+** - Core language
- **PyQt6** - GUI framework
- **Scapy** - Packet manipulation and capture
- **Matplotlib** - Data visualization
- **Pandas** - Data analysis
- **Jinja2** - Report templating

## Future Enhancements
- Machine learning-based anomaly detection
- Deep packet inspection (DPI)
- Integration with SIEM systems
- Support for custom detection rules
- Database logging for historical analysis
- Multi-interface simultaneous capture

## License
MIT License - see LICENSE file for details

## Acknowledgments
Built as a cybersecurity portfolio project demonstrating network security concepts and real-time threat detection.

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.
