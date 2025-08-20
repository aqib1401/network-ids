from PyQt6.QtWidgets import QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, QHeaderView
from PyQt6.QtGui import QColor, QBrush
import time

class ThreatLogTab(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout(self)
        
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Timestamp", "Severity", "Type", "Source IP", "Description"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.layout.addWidget(self.table)

    def add_alert(self, alert):
        """Adds an alert to the table."""
        row = self.table.rowCount()
        self.table.insertRow(row)
        
        ts = time.strftime('%H:%M:%S', time.localtime(alert['timestamp']))
        
        self.table.setItem(row, 0, QTableWidgetItem(ts))
        self.table.setItem(row, 1, QTableWidgetItem(alert['severity']))
        self.table.setItem(row, 2, QTableWidgetItem(alert['type']))
        self.table.setItem(row, 3, QTableWidgetItem(alert['src_ip']))
        self.table.setItem(row, 4, QTableWidgetItem(alert['description']))
        
        # Color coding
        bg_color = QColor(255, 255, 255)
        if alert['severity'] == 'Critical':
            bg_color = QColor(255, 200, 200)
        elif alert['severity'] == 'High':
            bg_color = QColor(255, 240, 200)
        elif alert['severity'] == 'Medium':
            bg_color = QColor(255, 255, 200)
        
        # Set background and text color (black for readability)
        text_color = QBrush(QColor(0, 0, 0))  # Black text
        for i in range(5):
            self.table.item(row, i).setBackground(bg_color)
            self.table.item(row, i).setForeground(text_color)
            
        self.table.scrollToBottom()
