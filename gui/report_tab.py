from PyQt6.QtWidgets import QWidget, QVBoxLayout, QPushButton, QLabel, QMessageBox
from PyQt6.QtCore import Qt

class ReportTab(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.layout = QVBoxLayout(self)
        self.layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        lbl_info = QLabel("Generate comprehensive reports of the captured traffic and detected threats.")
        lbl_info.setStyleSheet("font-size: 16px; margin-bottom: 20px;")
        self.layout.addWidget(lbl_info)
        
        btn_generate = QPushButton("Generate HTML/CSV/JSON Report")
        btn_generate.setStyleSheet("font-size: 14px; padding: 10px 20px; background-color: #4CAF50; color: white; border: none; border-radius: 5px;")
        btn_generate.clicked.connect(self.generate_report)
        self.layout.addWidget(btn_generate)

    def generate_report(self):
        try:
            path = self.main_window.generate_report()
            QMessageBox.information(self, "Success", f"Report generated successfully!\nSaved to: {path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate report: {e}")
