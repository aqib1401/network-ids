from PyQt6.QtWidgets import QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, QHeaderView
from PyQt6.QtCore import Qt
import time
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP

class PacketViewerTab(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout(self)
        
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["Time", "Source", "Destination", "Protocol", "Length", "Info"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.layout.addWidget(self.table)
        
        self.max_rows = 1000 # Limit rows to prevent memory issues

    def add_packet(self, packet):
        """Adds a packet to the table."""
        row = self.table.rowCount()
        if row >= self.max_rows:
            self.table.removeRow(0)
            row -= 1
            
        self.table.insertRow(row)
        
        timestamp = time.strftime('%H:%M:%S', time.localtime())
        src = "N/A"
        dst = "N/A"
        proto = "Other"
        length = str(len(packet))
        info = packet.summary()
        
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            p = packet[IP].proto
            if p == 6: proto = "TCP"
            elif p == 17: proto = "UDP"
            elif p == 1: proto = "ICMP"
            else: proto = str(p)
        elif ARP in packet:
            src = packet[ARP].psrc
            dst = packet[ARP].pdst
            proto = "ARP"
            
        self.table.setItem(row, 0, QTableWidgetItem(timestamp))
        self.table.setItem(row, 1, QTableWidgetItem(src))
        self.table.setItem(row, 2, QTableWidgetItem(dst))
        self.table.setItem(row, 3, QTableWidgetItem(proto))
        self.table.setItem(row, 4, QTableWidgetItem(length))
        self.table.setItem(row, 5, QTableWidgetItem(info))
        
        self.table.scrollToBottom()
