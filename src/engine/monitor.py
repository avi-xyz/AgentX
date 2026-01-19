import threading
import time
import logging
from scapy.all import ARP, Ether, send, sniff, conf, TCP, UDP, IP, IPv6, ICMP, ICMPv6DestUnreach, ICMPv6ND_NA, ICMPv6ND_NS, ICMPv6NDOptDstLLAddr
from scapy.layers.dns import DNS, DNSQR
from src.device_store import DeviceStore

# Suppress scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

class BandwidthMonitor(threading.Thread):
    def __init__(self, device_store: DeviceStore, gateway_ip: str, interface: str = None):
        super().__init__()
        self.device_store = device_store
        self.gateway_ip = gateway_ip
        self.interface = interface or conf.iface
        self.running = True
        self.targets = set() # IP addresses to monitor
        self.ipv6_targets = {} # Map MAC -> IPv6 address
        self.lock = threading.Lock()
        self.global_kill_switch = False

    def enable_monitoring(self, target_ip: str):
        with self.lock:
            self.targets.add(target_ip)

    def disable_monitoring(self, target_ip: str):
        with self.lock:
            if target_ip in self.targets:
                self.targets.remove(target_ip)

    def _get_macs(self, ip, window_seconds=600):
        # returns all MACs seen for this IP in the last X seconds
        now = time.time()
        macs = []
        
        for dev in self.device_store.get_all():
            if dev.ip == ip:
                if now - dev.last_seen < window_seconds:
                    macs.append(dev.mac)
        
        if not macs:
            # 2. Try Scapy Active ARP
            try:
                from scapy.all import srp1
                ans = srp1(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=1, verbose=False)
                if ans:
                    mac = ans.hwsrc
                    # Update store for next time
                    self.device_store.add_or_update(ip, mac)
                    macs.append(mac)
            except Exception:
                pass
            
        return list(set(macs)) # Deduplicate

    def _get_host_ip(self):
        import netifaces
        try:
            addrs = netifaces.ifaddresses(self.interface)
            if netifaces.AF_INET in addrs:
                return addrs[netifaces.AF_INET][0]['addr']
        except:
            pass
        return None

    def _spoof(self, target_ip, gateway_ip):
        """
        Send ARP packet to Target saying "I am Gateway"
        Send ARP packet to Gateway saying "I am Target"
        """
        target_macs = self._get_macs(target_ip)
        
        if not target_macs:
            return

        for mac in target_macs:
            self._spoof_with_mac(target_ip, mac, gateway_ip)

    def _restore(self, target_ip, gateway_ip):
        target_macs = self._get_macs(target_ip)
        gateway_macs = self._get_macs(gateway_ip)
        
        if not target_macs or not gateway_macs:
            return
            
        gw_mac = gateway_macs[0]
        
        for t_mac in target_macs:
             # Restore target: Gateway is at GatewayMAC
            send(ARP(op=2, pdst=target_ip, hwdst=t_mac, psrc=gateway_ip, hwsrc=gw_mac), count=3, verbose=False)
            # Restore gateway: Target is at TargetMAC
            send(ARP(op=2, pdst=gateway_ip, hwdst=gw_mac, psrc=target_ip, hwsrc=t_mac), count=3, verbose=False)

    def _update_stats(self, packet):
        # Callback for sniff
        if not packet.haslayer(Ether):
            return
            
        length = len(packet)
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        
        # Update devices based on flow
        # If src_mac is in our store, it's an Upload (from device)
        # If dst_mac is in our store, it's a Download (to device)
        
        # We find the device object
        # Note: This is O(N) lookup per packet, optimize with a dict if map is large
        # For home network (50 devices) it's likely fine, or use device_store.devices[mac]
        
        if src_mac in self.device_store.devices:
            dev = self.device_store.devices[src_mac]
            pass

    def block_target(self, target_ip):
        # We rely on the loop checking device.is_blocked
        with self.lock:
            if target_ip not in self.targets:
                self.targets.add(target_ip)
                
    def unblock_target(self, target_ip):
        """
        Immediately send corrective ARPs to restore connectivity.
        Uses proper peer-to-peer restoration, not MITM packets.
        """
        # Trigger full restoration burst
        for _ in range(10): # Increased burst for reliability
            self._restore(target_ip, self.gateway_ip)
            time.sleep(0.1)

    def _spoof_with_mac(self, target_ip, target_mac, gateway_ip):
        gateway_mac = self._get_macs(gateway_ip)
        if not gateway_mac: return
        gw_mac = gateway_mac[0]
        
        try:
            # Tell target I am gateway
            send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip), verbose=False)
            # Tell gateway I am target
            send(ARP(op=2, pdst=gateway_ip, hwdst=gw_mac, psrc=target_ip), verbose=False)
        except Exception as e:
            if "permission" in str(e).lower():
                self.running = False # Stop if we can't send
                logger.error("ARP Send failed: Permission denied. Stopping monitor.")

    def _get_current_time_str(self):
        import datetime
        return datetime.datetime.now().strftime("%H:%M")

    def should_block(self, device):
        if self.global_kill_switch:
            # logging.debug(f"Blocking {device.ip} (Global Kill Switch)")
            return True
            
        if device.is_blocked:
            # logging.debug(f"Blocking {device.ip} (Manual Block)")
            return True
            
        # Check Schedule
        if device.schedule_start and device.schedule_end:
            try:
                current_time = self._get_current_time_str()
                
                start = device.schedule_start
                end = device.schedule_end
                
                # Simple case: Start < End (e.g. 14:00 to 16:00)
                if start < end:
                    if start <= current_time < end:
                        # logging.debug(f"Blocking {device.ip} (Schedule: {start}-{end})")
                        return True
                # Overnight case: Start > End (e.g. 22:00 to 06:00)
                else:
                    if current_time >= start or current_time < end:
                        # logging.debug(f"Blocking {device.ip} (Overnight Schedule: {start}-{end})")
                        return True
            except Exception:
                pass
                
        return False

    def _enable_ip_forwarding(self):
        import subprocess
        import sys
        try:
            if sys.platform == "darwin":
                res = subprocess.run(["sysctl", "-w", "net.inet.ip.forwarding=1"], check=True, capture_output=True)
            elif sys.platform.startswith("linux"):
                res = subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True, capture_output=True)
            logger.info("IP Forwarding enabled")
            return True
        except Exception as e:
            logger.error(f"Failed to enable IP forwarding: {e}")
            logger.error("Blocking will fail without IP forwarding.")
            return False

    def _disable_ip_forwarding(self):
        import subprocess
        import sys
        try:
            if sys.platform == "darwin":
                subprocess.run(["sysctl", "-w", "net.inet.ip.forwarding=0"], check=True, capture_output=True)
            elif sys.platform.startswith("linux"):
                subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"], check=True, capture_output=True)
            logging.info("IP Forwarding disabled")
        except Exception as e:
            logging.error(f"Failed to disable IP forwarding: {e}")

    def run(self):
        # Enable IP forwarding
        self._enable_ip_forwarding()
        
        # Determine host IP to exclude
        host_ip = self._get_host_ip()
        logging.info(f"Monitor engine running. Interface: {self.interface}, Host IP: {host_ip}")

        # Start Sniffer Thread
        sniffer = threading.Thread(target=self._sniff_loop)
        sniffer.daemon = True
        sniffer.start()
        
        last_slow_tick = 0
        while self.running:
            current_tick = time.time()
            
            # 1. Take a snapshot of targets to minimize lock hold time
            with self.lock:
                current_targets = list(self.targets)
            
            # 2. Iterate outside the lock
            for target_ip in current_targets:
                if not self.running: break
                
                # Never spoof/block the host machine or the gateway itself as a target
                if target_ip == host_ip or target_ip == self.gateway_ip:
                    continue

                try:
                    # BLOCKING IO: _get_macs performs srp1 (ARP request)
                    macs = self._get_macs(target_ip)
                    for mac in macs:
                        dev = self.device_store.devices.get(mac)
                        if not dev: continue
                        
                        if self.should_block(dev):
                            # Blocked devices get high-frequency poisoning (every 0.5s)
                            self._spoof_block_with_mac(target_ip, mac, self.gateway_ip)
                        elif current_tick - last_slow_tick >= 2.0:
                            # Normal monitored devices get low-frequency spoofing (every 2s)
                            # BLOCKING IO: _spoof_with_mac performs send()
                            self._spoof_with_mac(target_ip, mac, self.gateway_ip)
                except Exception:
                    pass
            
            if current_tick - last_slow_tick >= 2.0:
                last_slow_tick = current_tick
                
            time.sleep(0.5) # Fast tick for active blocks

    def _spoof_block_with_mac(self, target_ip, target_mac, gateway_ip):
        gateway_macs = self._get_macs(gateway_ip)
        if not gateway_macs:
            logging.warning(f"Could not find MAC for gateway {gateway_ip}, blocking might fail.")
            return
        gw_mac = gateway_macs[0]
        
        bogus_mac = "00:00:00:00:00:01" 
        
        # 1. Standard ARP Poison (Tell target gateway is at bogus)
        send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=bogus_mac), count=1, verbose=False)
        # 2. Tell gateway target is at bogus
        send(ARP(op=2, pdst=gateway_ip, hwdst=gw_mac, psrc=target_ip, hwsrc=bogus_mac), count=1, verbose=False)
        
        # 3. Aggressive "IP Conflict" Trick
        send(ARP(op=2, psrc=target_ip, hwsrc="00:00:00:00:00:02", pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff"), count=1, verbose=False)
        
        # 4. IPv6 Block (the "iPhone Loophole")
        target_v6 = self.ipv6_targets.get(target_mac)
        if target_v6:
            # Fix: Pass target_v6 as target_v6, NOT target_mac
            self._spoof_block_v6(target_v6, target_v6)

    def _spoof_block_v6(self, target_v6, requested_v6):
        """
        Send bogus Neighbor Advertisements to block specific IPv6 path.
        """
        bogus_mac = "00:00:00:00:00:01"
        try:
            # Tell target that the IPv6 address they seek is at bogus_mac
            na = IPv6(src=requested_v6, dst=target_v6)/ICMPv6ND_NA(tgt=requested_v6, R=1, S=1, O=1)/ICMPv6NDOptDstLLAddr(lladdr=bogus_mac)
            send(na, verbose=False)
        except:
             pass

    def _spoof_block(self, target_ip, gateway_ip):
        """
        Send bogus ARP to both sides to cut connection.
        Tell Target: "Gateway is at 00:00:00:00:00:01"
        Tell Gateway: "Target is at 00:00:00:00:00:01"
        """
        target_mac = self._get_mac(target_ip)
        gateway_mac = self._get_mac(gateway_ip)
        
        if not target_mac or not gateway_mac:
            return
        
        # Dead end MAC (using a more standard looking but invalid one)
        bogus_mac = "00:00:00:00:00:01" 
        
        # logging.info(f"Poisoning block for {target_ip} <-> {gateway_ip}")
        
        # Tell target bogus gateway mac (dst=target, pdst=target_ip, psrc=gateway_ip, hwsrc=bogus_mac)
        send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=bogus_mac), count=2, verbose=False)
        # Tell gateway bogus target mac (dst=gateway, pdst=gateway_ip, psrc=target_ip, hwsrc=bogus_mac)
        send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=bogus_mac), count=2, verbose=False)

    def _sniff_loop(self):
        # Capture all IP types, including IPv6 on the selected interface
        try:
            sniff(iface=self.interface, 
                  store=False, 
                  prn=self._process_packet, 
                  filter="ip or ip6 or port 53",
                  stop_filter=lambda x: not self.running) 
        except Exception as e:
             logger.error(f"Sniffer crashed: {e}")

    def _process_packet(self, pkt):
        if not pkt.haslayer(Ether): return
        
        src_mac = pkt[Ether].src
        dst_mac = pkt[Ether].dst
        length = len(pkt)
        
        # IPv6 Detection & Discovery
        if pkt.haslayer(IPv6):
            if src_mac in self.device_store.devices:
                self.ipv6_targets[src_mac] = pkt[IPv6].src
                
            # If target is looking for its gateway via Neighbor Solicitation, poison it instantly
            if pkt.haslayer(ICMPv6ND_NS) and dst_mac == "ff:ff:ff:ff:ff:ff": # Multicast discovery
                 # We can't know for sure if it's the gateway being asked for 
                 # without knowing the gateway v6, but we can poison the reply 
                 # to the target if the target is one of our blocked ones.
                 if dst_mac in self.device_store.devices: # Wait, dst_mac is multicast here
                     pass
                 
                 # Better: If we see a solicitation FROM a blocked target, 
                 # send an unsolicited advertisement to it for the target it's looking for.
                 target_dev = self.device_store.devices.get(src_mac)
                 if target_dev and self.should_block(target_dev):
                      requested_v6 = pkt[ICMPv6ND_NS].tgt
                      self._spoof_block_v6(pkt[IPv6].src, requested_v6)
        
        # Upload Analysis
        if src_mac in self.device_store.devices:
            dev = self.device_store.devices[src_mac]
            
            # Active Blocking Feedback (ICMP Reject)
            if self.should_block(dev):
                if pkt.haslayer(IP):
                    # Send ICMP Destination Unreachable (Type 3, Code 13: Communication Admin Prohibited)
                    reject = IP(src=pkt[IP].dst, dst=pkt[IP].src)/ICMP(type=3, code=13)/pkt[IP]
                    send(reject, verbose=False)
                elif pkt.haslayer(IPv6):
                    # Send ICMPv6 Destination Unreachable (Type 1, Code 1: Communication with destination admin prohibited)
                    reject = IPv6(src=pkt[IPv6].dst, dst=pkt[IPv6].src)/ICMPv6DestUnreach(type=1, code=1)/pkt[IPv6]
                    send(reject, verbose=False)

            if not hasattr(dev, "total_up"): dev.total_up = 0
            dev.total_up += length
            
            # Check for SNI (TLS Client Hello) - TCP 443
            if pkt.haslayer(TCP) and pkt[TCP].dport == 443:
                 try:
                     payload = bytes(pkt[TCP].payload)
                     domain = self._extract_sni(payload)
                     if domain:
                         dev.last_sni = domain
                         if domain not in dev.domains:
                             dev.domains.append(domain)
                             if len(dev.domains) > 20: 
                                 dev.domains.pop(0)
                 except:
                     pass
            
            # Check for DNS Query - UDP 53
            if pkt.haslayer(UDP) and pkt[UDP].dport == 53:
                try:
                    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                        query = pkt[DNSQR].qname.decode("utf-8").rstrip(".")
                        if query:
                            dev.last_sni = query # Fallback/Alternative to SNI
                            if query not in dev.domains:
                                dev.domains.append(query)
                                if len(dev.domains) > 20:
                                    dev.domains.pop(0)
                except:
                    pass
            
        # Download Analysis
        if dst_mac in self.device_store.devices:
            dev = self.device_store.devices[dst_mac]
            if not hasattr(dev, "total_down"): dev.total_down = 0
            dev.total_down += length

    def _extract_sni(self, payload):
        """
        Lightweight manual SNI extraction to avoid Scapy TLS overhead.
        """
        try:
            # TLS Record Header (5 bytes)
            # Content Type: 0x16 (Handshake)
            # Version: 0x0301 (TLS 1.0) or 0x0303 (TLS 1.2)
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
                
        except Exception:
            return None
        return None
