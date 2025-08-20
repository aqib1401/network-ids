import logging
import time
from collections import defaultdict, deque
from scapy.layers.inet import TCP, IP, ICMP
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS
from core.utils import calculate_entropy

class ThreatDetector:
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger("ThreatDetector")
        
        # State tracking
        self.syn_tracker = defaultdict(list) # IP -> list of timestamps
        self.port_scan_tracker = defaultdict(set) # IP -> set of ports
        self.port_scan_times = defaultdict(list) # IP -> list of timestamps
        self.arp_table = {} # IP -> MAC
        self.icmp_tracker = deque(maxlen=1000) # list of timestamps
        
        # Thresholds
        self.syn_threshold = config['thresholds']['syn_flood']['max_syn_per_ip']
        self.syn_window = config['thresholds']['syn_flood']['time_window']
        self.scan_threshold = config['thresholds']['port_scan']['min_ports']
        self.scan_window = config['thresholds']['port_scan']['time_window']
        self.suspicious_ips = set(config.get('suspicious_ips', []))
        
    def check_packet(self, packet):
        """Analyzes a packet and returns a list of alerts."""
        alerts = []
        current_time = time.time()
        
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # E) Suspicious External Connections
            if src_ip in self.suspicious_ips or dst_ip in self.suspicious_ips:
                alerts.append({
                    'timestamp': current_time,
                    'severity': 'High',
                    'src_ip': src_ip,
                    'type': 'Suspicious IP',
                    'description': f"Traffic involving suspicious IP: {src_ip if src_ip in self.suspicious_ips else dst_ip}"
                })

            if TCP in packet:
                # A) Port Scan & B) SYN Flood
                if packet[TCP].flags == 'S': # SYN flag
                    self._check_syn_flood(src_ip, current_time, alerts)
                    self._check_port_scan(src_ip, packet[TCP].dport, current_time, alerts)
            
            if ICMP in packet:
                # G) ICMP Flood
                self._check_icmp_flood(current_time, alerts)

        if ARP in packet:
            # C) ARP Spoofing
            self._check_arp_spoofing(packet, alerts)
            
        if DNS in packet and packet[DNS].qr == 0: # Query
            # D) DNS Tunneling
            self._check_dns_tunneling(packet, alerts)
            
        return alerts

    def _check_syn_flood(self, src_ip, timestamp, alerts):
        # Clean old records
        self.syn_tracker[src_ip] = [t for t in self.syn_tracker[src_ip] if timestamp - t < self.syn_window]
        self.syn_tracker[src_ip].append(timestamp)
        
        if len(self.syn_tracker[src_ip]) > self.syn_threshold:
            alerts.append({
                'timestamp': timestamp,
                'severity': 'Critical',
                'src_ip': src_ip,
                'type': 'SYN Flood',
                'description': f"Potential SYN Flood: {len(self.syn_tracker[src_ip])} SYN packets in {self.syn_window}s"
            })
            # Clear to avoid spamming alerts
            self.syn_tracker[src_ip] = []

    def _check_port_scan(self, src_ip, dst_port, timestamp, alerts):
        # Clean old records
        self.port_scan_times[src_ip] = [t for t in self.port_scan_times[src_ip] if timestamp - t < self.scan_window]
        self.port_scan_times[src_ip].append(timestamp)
        
        # If we have enough packets in window, check distinct ports
        if len(self.port_scan_times[src_ip]) >= self.scan_threshold:
             # This is a simplification; ideally we track ports with timestamps. 
             # Here we just add the port and check count.
             self.port_scan_tracker[src_ip].add(dst_port)
             
             if len(self.port_scan_tracker[src_ip]) >= self.scan_threshold:
                 alerts.append({
                    'timestamp': timestamp,
                    'severity': 'High',
                    'src_ip': src_ip,
                    'type': 'Port Scan',
                    'description': f"Port Scan detected: {len(self.port_scan_tracker[src_ip])} distinct ports targeted"
                 })
                 self.port_scan_tracker[src_ip] = set() # Reset

    def _check_arp_spoofing(self, packet, alerts):
        op = packet[ARP].op
        if op == 2: # is-at (response)
            ip = packet[ARP].psrc
            mac = packet[ARP].hwsrc
            
            if ip in self.arp_table:
                if self.arp_table[ip] != mac:
                    alerts.append({
                        'timestamp': time.time(),
                        'severity': 'Critical',
                        'src_ip': ip,
                        'type': 'ARP Spoofing',
                        'description': f"ARP Spoofing detected! IP {ip} moved from {self.arp_table[ip]} to {mac}"
                    })
            self.arp_table[ip] = mac

    def _check_dns_tunneling(self, packet, alerts):
        if packet.haslayer(DNS) and packet[DNS].qd:
            qname = packet[DNS].qd.qname.decode('utf-8', errors='ignore')
            # Remove trailing dot
            if qname.endswith('.'):
                qname = qname[:-1]
                
            if len(qname) > self.config['dns_tunneling']['max_query_length']:
                alerts.append({
                    'timestamp': time.time(),
                    'severity': 'Medium',
                    'src_ip': packet[IP].src if IP in packet else "Unknown",
                    'type': 'DNS Tunneling',
                    'description': f"Long DNS Query ({len(qname)} chars): {qname[:30]}..."
                })
            
            entropy = calculate_entropy(qname)
            if entropy > self.config['dns_tunneling']['high_entropy_threshold']:
                 alerts.append({
                    'timestamp': time.time(),
                    'severity': 'Medium',
                    'src_ip': packet[IP].src if IP in packet else "Unknown",
                    'type': 'DNS Tunneling',
                    'description': f"High Entropy DNS Query ({entropy:.2f}): {qname[:30]}..."
                })

    def _check_icmp_flood(self, timestamp, alerts):
        self.icmp_tracker.append(timestamp)
        # Remove old
        while self.icmp_tracker and timestamp - self.icmp_tracker[0] > 1.0:
            self.icmp_tracker.popleft()
            
        if len(self.icmp_tracker) > self.config['thresholds']['icmp_flood']['max_icmp_per_sec']:
             alerts.append({
                'timestamp': timestamp,
                'severity': 'High',
                'src_ip': "Multiple/Unknown",
                'type': 'ICMP Flood',
                'description': f"ICMP Flood: {len(self.icmp_tracker)} packets/sec"
            })
             self.icmp_tracker.clear() # Avoid spam
