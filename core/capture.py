import logging
from PyQt6.QtCore import QThread, pyqtSignal
from scapy.all import sniff, conf, AsyncSniffer
from scapy.layers.inet import TCP, UDP, IP
from scapy.layers.l2 import Ether

class PacketCaptureThread(QThread):
    packet_captured = pyqtSignal(object)
    error_occurred = pyqtSignal(str)
    capture_started = pyqtSignal()
    
    def __init__(self, interface=None):
        super().__init__()
        self.interface = interface
        self.running = False
        self.sniffer = None
        self.logger = logging.getLogger("CaptureThread")

    def run(self):
        self.running = True
        self.logger.info(f"Starting capture on interface: {self.interface if self.interface else 'Default'}")
        print(f"\n[CAPTURE] Thread started for interface: {self.interface}")
        print(f"[CAPTURE] Scapy config: {conf.use_pcap}")
        
        try:
            # Use AsyncSniffer for better control
            print("[CAPTURE] Creating AsyncSniffer...")
            
            self.sniffer = AsyncSniffer(
                iface=self.interface,
                prn=self.process_packet,
                store=False
            )
            
            print("[CAPTURE] Starting sniffer...")
            self.sniffer.start()
            self.capture_started.emit()
            print("[CAPTURE] Sniffer running!")
            
            # Keep thread alive while running
            while self.running:
                self.msleep(100)  # Sleep for 100ms
            
            print("[CAPTURE] Stopping sniffer...")
            if self.sniffer:
                self.sniffer.stop()
            
        except PermissionError as e:
            error_msg = "Permission denied. Please run as Administrator!"
            self.logger.error(error_msg)
            print(f"[CAPTURE ERROR] {error_msg}")
            self.error_occurred.emit(error_msg)
        except Exception as e:
            error_msg = f"Error during packet capture: {e}"
            self.logger.error(error_msg)
            print(f"[CAPTURE ERROR] {error_msg}")
            self.error_occurred.emit(error_msg)
        
        self.logger.info("Capture stopped.")
        print("[CAPTURE] Thread stopped.")

    def process_packet(self, packet):
        """Callback for each captured packet."""
        if self.running:
            self.packet_captured.emit(packet)

    def stop(self):
        """Stops the capture thread."""
        print("[CAPTURE] Stop requested...")
        self.running = False
        if self.sniffer:
            try:
                self.sniffer.stop()
            except:
                pass
        self.wait(2000)  # Wait max 2 seconds for thread to finish

def get_interfaces():
    """Returns a list of available network interfaces."""
    try:
        print("[INTERFACES] Getting interface list...")
        ifaces = []
        for name, iface in conf.ifaces.items():
            ifaces.append(iface.name)
        print(f"[INTERFACES] Found {len(ifaces)} interfaces")
        return ifaces
    except Exception as e:
        logging.error(f"Error listing interfaces: {e}")
        print(f"[INTERFACES ERROR] {e}")
        return []
