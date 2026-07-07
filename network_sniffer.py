import sys
from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        
        # Determine protocol name
        protocol_name = "Unknown"
        if proto == 6:
            protocol_name = "TCP"
        elif proto == 17:
            protocol_name = "UDP"
        elif proto == 1:
            protocol_name = "ICMP"
            
        print(f"\n[+] New Packet: {src_ip} -> {dst_ip} | Protocol: {protocol_name}")
        
        # Extract payload if available
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            payload = bytes(packet[IP].payload)
            if payload:
                # Print printable characters, replace others with dots
                readable_payload = ''.join([chr(b) if 32 <= b < 127 else '.' for b in payload])
                print(f"    Payload Snippet: {readable_payload[:80]}")

def main():
    print("====== CodeAlpha Basic Network Sniffer ======")
    print("[*] Starting packet capture... Press Ctrl+C to stop.")
    try:
        # Sniff packets indefinitely, triggering the callback function for each
        sniff(prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n[*] Sniffer stopped safely.")
        sys.exit(0)
    except PermissionError:
        print("\n[!] Error: Root/Administrator privileges required to sniff packets.")
        sys.exit(1)

if __name__ == "__main__":
    main()