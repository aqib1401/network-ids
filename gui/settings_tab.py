from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QComboBox, QGroupBox, QFormLayout
from core.capture import get_interfaces

class SettingsTab(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout(self)
        
        # Interface Selection
        self.group_interface = QGroupBox("Capture Settings")
        self.layout.addWidget(self.group_interface)
        
        self.form_layout = QFormLayout()
        self.group_interface.setLayout(self.form_layout)
        
        self.combo_interface = QComboBox()
        self.refresh_interfaces()
        self.form_layout.addRow("Network Interface:", self.combo_interface)
        
        self.layout.addStretch()

    def refresh_interfaces(self):
        self.combo_interface.clear()
        interfaces = get_interfaces()
        if interfaces:
            self.combo_interface.addItems(interfaces)
        else:
            self.combo_interface.addItem("No interfaces found")
            
    def get_selected_interface(self):
        return self.combo_interface.currentText()
