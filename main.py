import sys
import logging
import os
from PyQt6.QtWidgets import QApplication
from gui.main_window import MainWindow
from core.utils import setup_logging

def main():
    # Setup logging
    setup_logging()
    
    # Create Application
    app = QApplication(sys.argv)
    app.setApplicationName("Network Intrusion Detection System")
    
    # Create Main Window
    window = MainWindow()
    window.show()
    
    # Execute
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
