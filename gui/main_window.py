import logging
from PyQt6.QtWidgets import QMainWindow, QWidget, QVBoxLayout, QTabWidget, QStatusBar, QToolBar, QMessageBox
from PyQt6.QtGui import QAction, QIcon
from PyQt6.QtCore import QTimer

from gui.dashboard_tab import DashboardTab
from gui.packet_viewer_tab import PacketViewerTab
from gui.threat_log_tab import ThreatLogTab
from gui.report_tab import ReportTab
from gui.settings_tab import SettingsTab

from core.capture import PacketCaptureThread
from core.detector import ThreatDetector
from core.analyzer import TrafficAnalyzer
from core.reporter import ReportGenerator
from core.utils import load_config

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Intrusion Detection System")
        self.resize(1200, 800)
        
        # Load Config
        self.config = load_config()
        
        # Initialize Core Modules
        self.capture_thread = None
        self.detector = ThreatDetector(self.config)
        self.analyzer = TrafficAnalyzer()
        self.reporter = ReportGenerator()
        self.alerts = [] # Store all alerts
        
        # UI Setup
        self._setup_ui()
        
        # Timer for updating dashboard
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_dashboard)
        self.timer.start(1000) # Update every second

    def _setup_ui(self):
        # Central Widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Toolbar
        toolbar = QToolBar()
        self.addToolBar(toolbar)
        
        self.action_start = QAction("Start Capture", self)
        self.action_start.triggered.connect(self.start_capture)
        toolbar.addAction(self.action_start)
        
        self.action_stop = QAction("Stop Capture", self)
        self.action_stop.triggered.connect(self.stop_capture)
        self.action_stop.setEnabled(False)
        toolbar.addAction(self.action_stop)
        
        toolbar.addSeparator()
        
        self.action_test = QAction("🧪 Inject Test Alerts", self)
        self.action_test.triggered.connect(self.inject_test_alerts)
        toolbar.addAction(self.action_test)
        
        # Tabs
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)
        
        self.tab_dashboard = DashboardTab()
        self.tab_packets = PacketViewerTab()
        self.tab_threats = ThreatLogTab()
        self.tab_report = ReportTab(self)
        self.tab_settings = SettingsTab()
        
        self.tabs.addTab(self.tab_dashboard, "Dashboard")
        self.tabs.addTab(self.tab_packets, "Packet Viewer")
        self.tabs.addTab(self.tab_threats, "Threat Log")
        self.tabs.addTab(self.tab_report, "Report")
        self.tabs.addTab(self.tab_settings, "Settings")
        
        # Status Bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")

    def start_capture(self):
        interface = self.tab_settings.get_selected_interface()
        if not interface or interface == "No interfaces found":
            QMessageBox.warning(self, "Error", "Please select a valid network interface in Settings.")
            return
        
        print(f"\n[MAIN] Starting capture on interface: {interface}")
        
        try:
            self.capture_thread = PacketCaptureThread(interface)
            self.capture_thread.packet_captured.connect(self.process_packet)
            self.capture_thread.error_occurred.connect(self.on_capture_error)
            self.capture_thread.capture_started.connect(self.on_capture_started)
            
            print("[MAIN] Starting thread...")
            self.capture_thread.start()
            
            self.action_start.setEnabled(False)
            self.action_stop.setEnabled(True)
            self.tab_settings.setEnabled(False)
            self.status_bar.showMessage(f"Initializing capture on {interface}...")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start capture: {e}")
            print(f"[MAIN ERROR] {e}")
        
    def on_capture_started(self):
        """Called when capture actually starts."""
        print("[MAIN] Capture confirmed started!")
        self.status_bar.showMessage(f"Capturing packets...")
        
    def on_capture_error(self, error_msg):
        """Handle capture errors."""
        QMessageBox.critical(self, "Capture Error", f"Packet capture failed:\n\n{error_msg}\n\nPlease ensure:\n1. Npcap is installed\n2. Running as Administrator\n3. Correct interface selected")
        self.stop_capture()

    def stop_capture(self):
        if self.capture_thread:
            self.capture_thread.stop()
            self.capture_thread = None
            
        self.action_start.setEnabled(True)
        self.action_stop.setEnabled(False)
        self.tab_settings.setEnabled(True)
        self.status_bar.showMessage("Capture stopped.")

    def process_packet(self, packet):
        # 1. Analyze Traffic
        self.analyzer.update(packet)
        
        # 2. Detect Threats
        new_alerts = self.detector.check_packet(packet)
        if new_alerts:
            for alert in new_alerts:
                self.alerts.append(alert)
                self.tab_threats.add_alert(alert)
            self.tab_dashboard.update_alert_count(len(self.alerts))
        
        # 3. Update Packet Viewer (throttle to avoid UI freeze)
        # Only update every 10th packet or so if high load, but for now we do all
        # Actually, let's just add it.
        self.tab_packets.add_packet(packet)

    def update_dashboard(self):
        stats = self.analyzer.get_stats()
        self.tab_dashboard.update_stats(stats)

    def generate_report(self):
        stats = self.analyzer.get_stats()
        return self.reporter.generate_reports(stats, self.alerts, self.config)
    
    def inject_test_alerts(self):
        """Inject sample alerts for testing/demonstration purposes."""
        import time
        
        reply = QMessageBox.question(
            self, 
            "Inject Test Alerts",
            "This will inject 7 sample threat alerts into the system for testing.\n\n"
            "This is useful for:\n"
            "• Testing the GUI\n"
            "• Demonstrating the reporting features\n"
            "• Portfolio/presentation purposes\n\n"
            "Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        print("\n[TEST MODE] Injecting sample alerts...")
        
        test_alerts = [
            {
                'timestamp': time.time(),
                'severity': 'High',
                'src_ip': '192.168.1.100',
                'type': 'Port Scan',
                'description': 'Port Scan detected: 15 distinct ports targeted'
            },
            {
                'timestamp': time.time() + 1,
                'severity': 'Critical',
                'src_ip': '10.0.0.50',
                'type': 'SYN Flood',
                'description': 'Potential SYN Flood: 65 SYN packets in 30s'
            },
            {
                'timestamp': time.time() + 2,
                'severity': 'High',
                'src_ip': 'Multiple/Unknown',
                'type': 'ICMP Flood',
                'description': 'ICMP Flood: 120 packets/sec'
            },
            {
                'timestamp': time.time() + 3,
                'severity': 'Medium',
                'src_ip': '192.168.1.105',
                'type': 'DNS Tunneling',
                'description': 'Long DNS Query (75 chars): aaaaaaaaaaaaaaaaaaaaaaaaaaaa...'
            },
            {
                'timestamp': time.time() + 4,
                'severity': 'Medium',
                'src_ip': '192.168.1.105',
                'type': 'DNS Tunneling',
                'description': 'High Entropy DNS Query (5.2): x7k9m2p4q8r1s3t6u9v2w5...'
            },
            {
                'timestamp': time.time() + 5,
                'severity': 'High',
                'src_ip': '10.0.0.200',
                'type': 'Suspicious IP',
                'description': 'Traffic involving suspicious IP: 10.0.0.200'
            },
            {
                'timestamp': time.time() + 6,
                'severity': 'Critical',
                'src_ip': '192.168.1.1',
                'type': 'ARP Spoofing',
                'description': 'ARP Spoofing detected! IP 192.168.1.1 moved from aa:bb:cc:dd:ee:ff to 11:22:33:44:55:66'
            }
        ]
        
        for alert in test_alerts:
            self.alerts.append(alert)
            self.tab_threats.add_alert(alert)
            print(f"  ✓ Added {alert['type']} alert")
        
        self.tab_dashboard.update_alert_count(len(self.alerts))
        
        QMessageBox.information(
            self,
            "Test Alerts Injected",
            f"Successfully injected {len(test_alerts)} test alerts!\n\n"
            "Check:\n"
            "• Threat Log tab - See all alerts\n"
            "• Dashboard - Updated alert count\n"
            "• Report tab - Generate HTML report"
        )
        
        print(f"[TEST MODE] Injected {len(test_alerts)} alerts successfully!")
    
    def closeEvent(self, event):
        self.stop_capture()
        event.accept()
