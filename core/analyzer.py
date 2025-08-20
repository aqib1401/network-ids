import logging
from collections import Counter, defaultdict
import time
from scapy.layers.inet import TCP, UDP, IP, ICMP
from scapy.layers.l2 import Ether, ARP

class TrafficAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger("TrafficAnalyzer")
        
        # Stats
        self.total_packets = 0
        self.start_time = time.time()
        self.protocol_counts = Counter()
        self.src_ip_counts = Counter()
        self.dst_ip_counts = Counter()
        self.packet_rate_history = [] # (timestamp, count)
        
        # For rate calculation
        self.window_start = time.time()
        self.window_count = 0

    def update(self, packet):
        """Updates statistics with a new packet."""
        self.total_packets += 1
        self.window_count += 1
        
        current_time = time.time()
        
        # Rate calculation (every 1 second)
        if current_time - self.window_start >= 1.0:
            self.packet_rate_history.append((current_time, self.window_count))
            self.window_count = 0
            self.window_start = current_time
            
            # Keep history limited
            if len(self.packet_rate_history) > 60: # Keep last 60 seconds
                self.packet_rate_history.pop(0)

        # Protocol analysis
        if IP in packet:
            proto = packet[IP].proto
            if proto == 6:
                self.protocol_counts['TCP'] += 1
            elif proto == 17:
                self.protocol_counts['UDP'] += 1
            elif proto == 1:
                self.protocol_counts['ICMP'] += 1
            else:
                self.protocol_counts['Other IP'] += 1
                
            self.src_ip_counts[packet[IP].src] += 1
            self.dst_ip_counts[packet[IP].dst] += 1
            
        elif ARP in packet:
            self.protocol_counts['ARP'] += 1
        else:
            self.protocol_counts['Other'] += 1

    def get_stats(self):
        """Returns a dictionary of current statistics."""
        duration = time.time() - self.start_time
        pps = self.packet_rate_history[-1][1] if self.packet_rate_history else 0
        
        return {
            'total_packets': self.total_packets,
            'duration': duration,
            'pps': pps,
            'protocols': dict(self.protocol_counts),
            'top_src_ips': self.src_ip_counts.most_common(10),
            'top_dst_ips': self.dst_ip_counts.most_common(10)
        }
