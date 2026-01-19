import threading
import time
import logging
from scapy.all import srp, Ether, ARP, conf
from src.device_store import DeviceStore
from src.engine.classifier import DeviceClassifier

# Suppress scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

class NetworkScanner(threading.Thread):
    def __init__(self, device_store: DeviceStore, interface: str = None, scan_interval: int = 30):
        super().__init__()
        self.device_store = device_store
        self.interface = interface or conf.iface
        self.scan_interval = scan_interval
        self.scan_interval = scan_interval
        self.running = True
        
        # Determine local cache path
        import os
        self.vendors = {}
        cache_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mac-vendors.txt")
        self.classifier = DeviceClassifier()
        
        try:
             # Load vendors synchronously into a simple dict
             with open(cache_path, "rb") as f:
                 for line in f:
                     if b":" in line:
                         prefix, vendor = line.split(b":", 1)
                         self.vendors[prefix.decode("utf8")] = vendor.strip().decode("utf8")
             logging.info(f"Loaded {len(self.vendors)} vendors from {cache_path}")
        except Exception as e:
            logging.error(f"Vendor load failed: {e}")


    def get_vendor(self, mac_address):
        try:
            # Sanitize MAC: 00:00:00 -> 000000
            clean_mac = mac_address.replace(":", "").replace("-", "").upper()
            
            # 1. Check for Private/Random MAC (Locally Administered Bit) first
            # The second least significant bit of the first octet
            try:
                first_octet = int(clean_mac[:2], 16)
                if (first_octet & 0b00000010):
                    return "Private/Random"
            except:
                pass

            # 2. Check OUI Database
            prefix = clean_mac[:6]
            if prefix in self.vendors:
                return self.vendors[prefix]
                
            return "Unknown"
        except Exception as e:
            logging.error(f"Lookup error: {e}")
            return "Unknown"

    def scan(self):
        try:
            # Auto-detect interface with Internet access
            import netifaces
            import ipaddress
            
            if self.interface is None or self.interface == conf.iface:
                try:
                    # Get default gateway interface
                    gws = netifaces.gateways()
                    default_gw = gws.get('default', {}).get(netifaces.AF_INET)
                    if default_gw:
                        self.interface = default_gw[1]
                except:
                    pass

            # Calculate Subnet
            try:
                iface_details = netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0]
                ip = iface_details['addr']
                mask = iface_details['netmask']
                # Calculate network
                network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                subnet = str(network)
            except Exception as e:
                logging.error(f"Could not determine subnet: {e}")
                subnet = "192.168.1.0/24" # Fallback

            # logging.info(f"Scanning {subnet} on {self.interface}...")
            
            ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet), 
                             iface=self.interface, 
                             timeout=2, 
                             verbose=0)

            for sent, received in ans:
                ip = received.psrc
                mac = received.hwsrc
                logging.info(f"Discovered: IP={ip}, MAC={mac}")
                vendor = self.get_vendor(mac)
                device = self.device_store.add_or_update(ip, mac, vendor)
                
                # Run Classification
                category, confidence = self.classifier.classify(device)
                device.category = category
                device.confidence = confidence
                
        except Exception as e:
            logging.error(f"Scan error: {e}")

    def run(self):
        # Start Passive Listener Thread
        listener = threading.Thread(target=self._passive_listener)
        listener.daemon = True
        listener.start()
        
        # Periodic Active Scan
        while self.running:
            self.scan()
            time.sleep(self.scan_interval)

    def _passive_listener(self):
        """
        Listen for ANY ARP packets to pick up devices instantly 
        without waiting for the next scan cycle.
        """
        from scapy.all import sniff
        def handle_arp(pkt):
            if ARP in pkt and pkt[ARP].op in (1, 2): # Request or Reply
                src_mac = pkt[ARP].hwsrc
                src_ip = pkt[ARP].psrc
                
                # Update Store Instantly
                if src_ip != "0.0.0.0":
                    vendor = self.get_vendor(src_mac)
                    # We reuse logic, maybe methodize it?
                    device = self.device_store.add_or_update(src_ip, src_mac, vendor)
                    
                    # Quick Classify if new
                    if device.category.value == "Unknown":
                        category, confidence = self.classifier.classify(device)
                        device.category = category
                        device.confidence = confidence

        try:
            sniff(filter="arp", 
                  prn=handle_arp, 
                  store=0,
                  stop_filter=lambda x: not self.running)
        except Exception as e:
            logging.error(f"Passive listener error: {e}")

    def stop(self):
        self.running = False
