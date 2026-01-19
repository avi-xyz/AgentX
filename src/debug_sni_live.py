from scapy.all import sniff, conf, TCP
import logging

# Copy-paste the extractor from monitor.py to ensure identical logic
def _extract_sni(payload):
    try:
        # TLS Record Header (5 bytes)
        # Content Type: 0x16 (Handshake)
        if len(payload) < 50: return None
        if payload[0] != 0x16: return None
        
        # Handshake Header
        # Type: 0x01 (Client Hello)
        if payload[5] != 0x01: return None
        
        # Skip Record Header (5) + Handshake Header (4) + Version (2) + Random (32)
        cursor = 5 + 4 + 2 + 32
        
        # Session ID
        params_len = payload[cursor]
        cursor += 1 + params_len
        
        # Cipher Suites
        cipher_len = int.from_bytes(payload[cursor:cursor+2], 'big')
        cursor += 2 + cipher_len
        
        # Compression
        comp_len = payload[cursor]
        cursor += 1 + comp_len
        
        # Extensions
        if cursor + 2 > len(payload): return None
        ext_len = int.from_bytes(payload[cursor:cursor+2], 'big')
        cursor += 2
        
        end = cursor + ext_len
        while cursor < end:
            if cursor + 4 > len(payload): break
            ext_type = int.from_bytes(payload[cursor:cursor+2], 'big')
            ext_data_len = int.from_bytes(payload[cursor+2:cursor+4], 'big')
            cursor += 4
            
            # Extension 0x00 is SNI
            if ext_type == 0x00:
                # SNI List Length (2)
                sni_list_len = int.from_bytes(payload[cursor:cursor+2], 'big')
                cursor += 2
                # SNI Type (1) - 0x00 HostName
                sni_type = payload[cursor]
                cursor += 1
                # SNI Length (2)
                sni_len = int.from_bytes(payload[cursor:cursor+2], 'big')
                cursor += 2
                
                hostname = payload[cursor:cursor+sni_len].decode("utf8")
                return hostname
            
            cursor += ext_data_len
            
    except Exception as e:
        print(f"Error parsing: {e}")
        return None
    return None

def packet_callback(pkt):
    if pkt.haslayer(TCP) and pkt[TCP].dport == 443:
        if pkt[TCP].payload:
            payload = bytes(pkt[TCP].payload)
            # Filter for TLS Handshake (0x16)
            if len(payload) > 0 and payload[0] == 0x16:
                print(f"[TCP] TLS Handshake detected from {pkt[1].src}")
                domain = _extract_sni(payload)
                if domain:
                    print(f"   >>> SNI: {domain}")
                else:
                    print(f"   >>> Failed to extract SNI")

if __name__ == "__main__":
    print(f"Sniffing TCP/UDP 443 + UDP 53 on {conf.iface}...")
    def extended_callback(pkt):
        if pkt.haslayer(TCP) and pkt[TCP].dport == 443:
             packet_callback(pkt)
        elif pkt.haslayer("UDP"):
             if pkt["UDP"].dport == 443:
                 print(f"[UDP] QUIC/HTTP3 detected from {pkt[1].src}")
             elif pkt["UDP"].dport == 53:
                 try:
                     from scapy.layers.dns import DNS, DNSQR
                     if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                         query = pkt[DNSQR].qname.decode("utf-8")
                         print(f"[DNS] Query from {pkt[1].src}: {query}")
                 except:
                     pass

    try:
        sniff(filter="port 443 or port 53", prn=extended_callback, store=0)
    except KeyboardInterrupt:
        print("Stopping.")
