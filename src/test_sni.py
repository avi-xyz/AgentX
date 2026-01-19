from src.engine.monitor import BandwidthMonitor
from src.device_store import DeviceStore

def test_sni_parser():
    print("Testing SNI Parser...")
    store = DeviceStore()
    monitor = BandwidthMonitor(store, "1.1.1.1")
    
    # Construct a minimal TLS Client Hello Payload manually
    # Record Header (5): 16 03 01 00 2D
    # Handshake Header (4): 01 00 00 29
    # Version (2): 03 03
    # Random (32): ...
    # Session ID (1): 00
    # Cipher (2): 00 02 00 2F
    # Comp (1): 01 00
    # Ext Len (2): 00 17
    # Ext (SNI): 00 00 00 13 00 11 00 00 0E 65 78 61 6D 70 6C 65 2E 63 6F 6D (example.com)
    
    # 00 00 (Type SNI)
    # 00 13 (Len 19)
    # 00 11 (List Len 17)
    # 00 (Type HostName)
    # 00 0E (Len 14)
    # example.com
    
    payload = bytearray([
        0x16, 0x03, 0x01, 0x00, 0x3A, # Record Header
        0x01, 0x00, 0x00, 0x36,       # Handshake Header
        0x03, 0x03,                   # Version
    ])
    payload.extend(b"\x00" * 32)      # Random
    payload.append(0x00)              # Session ID Len
    payload.extend(b"\x00\x02\x00\x2F") # Cipher Suites
    payload.extend(b"\x01\x00")       # Compression
    
    # Extensions
    # SNI Extension
    sni_hostname = b"example.com"
    sni_len = len(sni_hostname)
    sni_list_len = sni_len + 3
    ext_data_len = sni_list_len + 2
    
    payload.extend(int(ext_data_len + 4).to_bytes(2, 'big')) # Total Ext Len
    
    payload.extend(b"\x00\x00") # Ext Type (SNI)
    payload.extend(int(ext_data_len).to_bytes(2, 'big')) # Ext Data Len
    
    payload.extend(int(sni_list_len).to_bytes(2, 'big')) # List Len
    payload.append(0x00) # SNI Type Hostname
    payload.extend(int(sni_len).to_bytes(2, 'big')) # SNI Len
    payload.extend(sni_hostname)
    
    print(f"Payload len: {len(payload)}")
    
    sni = monitor._extract_sni(payload)
    print(f"Extracted SNI: {sni}")
    
    assert sni == "example.com"
    print("Test Passed!")

if __name__ == "__main__":
    test_sni_parser()
