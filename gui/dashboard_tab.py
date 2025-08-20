from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QGridLayout
from PyQt6.QtCore import QTimer, Qt
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import matplotlib.pyplot as plt

class DashboardTab(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout(self)
        
        # Top Stats Row
        self.stats_layout = QHBoxLayout()
        self.lbl_total_packets = self._create_stat_card("Total Packets", "0")
        self.lbl_pps = self._create_stat_card("Packets / Sec", "0")
        self.lbl_alerts = self._create_stat_card("Threat Alerts", "0")
        self.layout.addLayout(self.stats_layout)
        
        # Graphs Area
        self.graphs_layout = QGridLayout()
        self.layout.addLayout(self.graphs_layout)
        
        # Protocol Pie Chart
        self.fig_proto = Figure(figsize=(5, 4), dpi=100)
        self.canvas_proto = FigureCanvas(self.fig_proto)
        self.ax_proto = self.fig_proto.add_subplot(111)
        self.ax_proto.set_title("Protocol Distribution")
        self.graphs_layout.addWidget(self.canvas_proto, 0, 0)
        
        # PPS Line Graph
        self.fig_pps = Figure(figsize=(5, 4), dpi=100)
        self.canvas_pps = FigureCanvas(self.fig_pps)
        self.ax_pps = self.fig_pps.add_subplot(111)
        self.ax_pps.set_title("Traffic Volume (PPS)")
        self.graphs_layout.addWidget(self.canvas_pps, 0, 1)
        
        # Data containers for plotting
        self.pps_data_x = []
        self.pps_data_y = []

    def _create_stat_card(self, title, value):
        container = QWidget()
        container.setStyleSheet("background-color: #f0f0f0; border-radius: 10px; padding: 10px;")
        layout = QVBoxLayout(container)
        
        lbl_title = QLabel(title)
        lbl_title.setStyleSheet("font-size: 14px; color: #666;")
        lbl_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        lbl_value = QLabel(value)
        lbl_value.setStyleSheet("font-size: 24px; font-weight: bold; color: #333;")
        lbl_value.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        layout.addWidget(lbl_title)
        layout.addWidget(lbl_value)
        self.stats_layout.addWidget(container)
        return lbl_value

    def update_stats(self, stats):
        """Updates the UI with new statistics."""
        self.lbl_total_packets.setText(str(stats['total_packets']))
        self.lbl_pps.setText(str(stats['pps']))
        
        # Update Protocol Chart
        self.ax_proto.clear()
        if stats['protocols']:
            self.ax_proto.pie(stats['protocols'].values(), labels=stats['protocols'].keys(), autopct='%1.1f%%')
        self.ax_proto.set_title("Protocol Distribution")
        self.canvas_proto.draw()
        
        # Update PPS Graph
        # We need to maintain history here or get it from stats
        # Assuming stats['pps'] is instantaneous, we append to local history for display
        # In a real app, we might want to get the full history from analyzer
        self.pps_data_y.append(stats['pps'])
        if len(self.pps_data_y) > 60:
            self.pps_data_y.pop(0)
        self.pps_data_x = list(range(len(self.pps_data_y)))
        
        self.ax_pps.clear()
        self.ax_pps.plot(self.pps_data_x, self.pps_data_y)
        self.ax_pps.set_title("Traffic Volume (PPS)")
        self.canvas_pps.draw()

    def update_alert_count(self, count):
        self.lbl_alerts.setText(str(count))
