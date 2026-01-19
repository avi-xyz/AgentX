import threading
import socket
import struct
import logging
from src.device_store import DeviceStore

# Suppress scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

class DiscoveryListener(threading.Thread):
    def __init__(self, device_store: DeviceStore):
        super().__init__()
        self.device_store = device_store
        self.running = True
        self.threads = []

    def run(self):
        # Start mDNS Listener
        t1 = threading.Thread(target=self._listen_mdns)
        t1.daemon = True
        t1.start()
        self.threads.append(t1)

        # Start SSDP Listener
        t2 = threading.Thread(target=self._listen_ssdp)
        t2.daemon = True
        t2.start()
        self.threads.append(t2)
        
        while self.running:
            import time
            time.sleep(1)

    def stop(self):
        self.running = False
        for t in self.threads:
            if t.is_alive():
                t.join(timeout=1.0)

    def _listen_mdns(self):
        """
        Listen for mDNS responses on UDP 5353
        """
        MCAST_GRP = '224.0.0.251'
        MCAST_PORT = 5353
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # MacOS specific binding
        try:
            sock.bind(('', MCAST_PORT))
        except:
            return

        mreq = struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        
        while self.running:
            try:
                data, addr = sock.recvfrom(10240)
                src_ip = addr[0]
                
                # Update Store (Just ensure it exists first? We need MAC)
                # But we only have IP here.
                # DeviceStore needs MAC. We must find MAC from IP or wait for ARP.
                
                # Parse mDNS manually or regex? 
                # Let's try simple string extraction for .local names
                try:
                    content = data.decode('utf-8', errors='ignore')
                    # Look for something.local
                    import re
                    match = re.search(r'[\w-]+\.local', content)
                    if match:
                        hostname = match.group(0)
                        self._update_device_info(src_ip, hostname=hostname, service="mDNS")
                except:
                    pass
            except:
                pass

    def _listen_ssdp(self):
        """
        Listen for SSDP NOTIFY on UDP 1900
        """
        MCAST_GRP = '239.255.255.250'
        MCAST_PORT = 1900
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            sock.bind(('', MCAST_PORT))
        except:
            return

        mreq = struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.settimeout(1.0) # Allow checking self.running

        while self.running:
            try:
                data, addr = sock.recvfrom(10240)
                src_ip = addr[0]
                content = data.decode('utf-8', errors='ignore')
                
                # Extract Server/location
                service = "SSDP"
                if "SERVER:" in content:
                    lines = content.splitlines()
                    for line in lines:
                        if line.startswith("SERVER:"):
                            service = line.split(":", 1)[1].strip()
                            break
                            
                self._update_device_info(src_ip, service=service)
            except:
                pass

    def _update_device_info(self, ip, hostname=None, service=None):
        # We need to find the device by IP in our store
        # This is O(N) but N is small (home network)
        target_dev = None
        for dev in self.device_store.get_all():
             if dev.ip == ip:
                 target_dev = dev
                 break
        
        if target_dev:
            if hostname and not target_dev.hostname:
                target_dev.hostname = hostname
            
            if service:
                if service not in target_dev.mdns_services:
                    target_dev.mdns_services.append(service)
                    # Limit
                    if len(target_dev.mdns_services) > 10:
                        target_dev.mdns_services.pop(0)

