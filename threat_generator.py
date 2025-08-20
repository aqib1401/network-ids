"""
Threat Traffic Generator - Triggers NIDS Alerts
This generates traffic patterns that should trigger the threat detection system.
Run this WHILE the NIDS is capturing on your WiFi interface.
"""

import time
import random
from scapy.all import send, IP, TCP, UDP, ICMP, DNS, DNSQR, sr1, conf

# Disable verbose output
conf.verb = 0

def test_connectivity():
    """Test if we can reach the internet."""
    print("[TEST] Checking connectivity...")
    try:
        pkt = IP(dst="8.8.8.8")/ICMP()
        reply = sr1(pkt, timeout=2, verbose=0)
        if reply:
            print("  ✓ Internet connectivity OK")
            return True
        else:
            print("  ✗ No response from 8.8.8.8")
            return False
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return False

def generate_port_scan_attack():
    """
    Port Scan Detection Test
    Sends SYN packets to multiple ports from the same source.
    Should trigger: Port Scan alert
    """
    print("\n[ATTACK 1] Port Scan Simulation")
    print("  Scanning ports 20-35 on 1.1.1.1...")
    
    target = "1.1.1.1"
    
    for port in range(20, 36):  # 16 ports (exceeds threshold of 10)
        pkt = IP(dst=target)/TCP(dport=port, flags="S", sport=random.randint(1024, 65535))
        send(pkt, verbose=0)
        print(f"  → Port {port}", end="\r")
        time.sleep(0.1)
    
    print("\n  ✓ Port scan complete (16 ports)")
    print("  Expected Alert: Port Scan (High)")

def generate_syn_flood_attack():
    """
    SYN Flood Detection Test
    Sends many SYN packets from spoofed IPs.
    Should trigger: SYN Flood alert
    """
    print("\n[ATTACK 2] SYN Flood Simulation")
    print("  Sending 70 SYN packets to 8.8.8.8...")
    
    target = "8.8.8.8"
    
    for i in range(70):  # Exceeds threshold of 50
        # Spoof source IP
        src_ip = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
        pkt = IP(src=src_ip, dst=target)/TCP(dport=80, flags="S", sport=random.randint(1024, 65535))
        send(pkt, verbose=0)
        if (i + 1) % 10 == 0:
            print(f"  → Sent {i+1}/70 packets", end="\r")
        time.sleep(0.02)
    
    print("\n  ✓ SYN flood complete (70 packets)")
    print("  Expected Alert: SYN Flood (Critical)")

def generate_icmp_flood_attack():
    """
    ICMP Flood Detection Test
    Sends rapid ICMP echo requests.
    Should trigger: ICMP Flood alert
    """
    print("\n[ATTACK 3] ICMP Flood Simulation")
    print("  Sending 120 ICMP packets rapidly...")
    
    target = "8.8.8.8"
    
    for i in range(120):  # Exceeds threshold of 100
        pkt = IP(dst=target)/ICMP()
        send(pkt, verbose=0)
        if (i + 1) % 20 == 0:
            print(f"  → Sent {i+1}/120 packets", end="\r")
        time.sleep(0.005)
    
    print("\n  ✓ ICMP flood complete (120 packets)")
    print("  Expected Alert: ICMP Flood (High)")

def generate_dns_tunneling_attack():
    """
    DNS Tunneling Detection Test
    Sends suspicious DNS queries.
    Should trigger: DNS Tunneling alert
    """
    print("\n[ATTACK 4] DNS Tunneling Simulation")
    
    # Long DNS query
    print("  Sending long DNS query (>50 chars)...")
    long_query = "a" * 65 + ".example.com"
    pkt = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=long_query))
    send(pkt, verbose=0)
    print(f"  ✓ Sent query: {long_query[:30]}... ({len(long_query)} chars)")
    
    time.sleep(0.5)
    
    # High entropy DNS query
    print("  Sending high-entropy DNS query...")
    entropy_query = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=50)) + ".malicious.com"
    pkt = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=entropy_query))
    send(pkt, verbose=0)
    print(f"  ✓ Sent query: {entropy_query[:30]}...")
    
    print("  Expected Alert: DNS Tunneling (Medium) - 2 alerts")

def generate_suspicious_ip_traffic():
    """
    Suspicious IP Detection Test
    Sends traffic from/to suspicious IPs defined in config.
    Should trigger: Suspicious IP alert
    """
    print("\n[ATTACK 5] Suspicious IP Traffic")
    print("  Sending traffic from suspicious IP (10.0.0.200)...")
    
    # This IP is in the config.yaml suspicious_ips list
    pkt = IP(src="10.0.0.200", dst="8.8.8.8")/TCP(dport=443, flags="A", sport=random.randint(1024, 65535))
    send(pkt, verbose=0)
    
    print("  ✓ Sent packet from 10.0.0.200")
    print("  Expected Alert: Suspicious IP (High)")

def main():
    print("="*60)
    print("NIDS Threat Traffic Generator")
    print("="*60)
    print()
    print("This will generate attack patterns to test the NIDS.")
    print("Make sure the NIDS is running and capturing on WiFi!")
    print()
    
    if not test_connectivity():
        print("\n⚠ Warning: No internet connectivity detected.")
        print("Some attacks may not work properly.")
        input("Press Enter to continue anyway, or Ctrl+C to abort...")
    
    print("\n" + "="*60)
    print("Starting Attack Simulation...")
    print("="*60)
    
    # Run all attacks
    generate_port_scan_attack()
    time.sleep(2)
    
    generate_syn_flood_attack()
    time.sleep(2)
    
    generate_icmp_flood_attack()
    time.sleep(2)
    
    generate_dns_tunneling_attack()
    time.sleep(2)
    
    generate_suspicious_ip_traffic()
    
    print("\n" + "="*60)
    print("Attack Simulation Complete!")
    print("="*60)
    print()
    print("Check your NIDS now:")
    print("  • Dashboard: Should show increased packet count")
    print("  • Threat Log: Should show 6-7 alerts")
    print("  • Expected alerts:")
    print("    - Port Scan (High)")
    print("    - SYN Flood (Critical)")
    print("    - ICMP Flood (High)")
    print("    - DNS Tunneling (Medium) x2")
    print("    - Suspicious IP (High)")
    print()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nAborted by user.")
    except Exception as e:
        print(f"\n\nError: {e}")
    
    input("\nPress Enter to exit...")
