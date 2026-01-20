from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Set, Dict

class DeviceCategory(Enum):
    UNKNOWN = "Unknown"
    MOBILE = "Mobile"          # iPhone, Android
    PC = "PC/Laptop"           # MacBook, Windows PC
    ROUTER = "Router"          # Gateway
    IOT = "IoT/Smart Home"     # Bulbs, Plugs
    MEDIA = "Media"            # TV, Chromecast, AppleTV
    SERVER = "Server"          # Raspberry Pi, NAS
    PRINTER = "Printer"

@dataclass
class Device:
    ip: str
    mac: str
    vendor: str = "Unknown"
    hostname: str = ""
    
    # Categorization
    category: DeviceCategory = DeviceCategory.UNKNOWN
    confidence: int = 0
    os_guess: str = ""
    open_ports: List[int] = field(default_factory=list)
    mdns_services: List[str] = field(default_factory=list)
    
    # Bandwidth Stats
    upload_rate: float = 0.0   # Bytes/sec
    download_rate: float = 0.0 # Bytes/sec
    total_up: int = 0
    total_down: int = 0
    history_up: List[float] = field(default_factory=list)
    history_down: List[float] = field(default_factory=list)
    
    # Activity
    domains: List[str] = field(default_factory=list) # Recent SNI domains
    last_sni: str = ""
    
    is_blocked: bool = False # Kill Switch Status
    
    # Schedule (HH:MM)
    schedule_start: str = ""
    schedule_end: str = ""
    
    last_known_ip: str = "" # Persistent even if current IP is blank
    last_seen: float = 0.0

    def to_dict(self):
        return {
            "ip": self.ip,
            "mac": self.mac,
            "vendor": self.vendor,
            "hostname": self.hostname,
            "category": self.category.value,
            "confidence": self.confidence,
            "os_guess": self.os_guess,
            "open_ports": self.open_ports,
            "mdns_services": self.mdns_services,
            "total_up": self.total_up,
            "total_down": self.total_down,
            "history_up": self.history_up,
            "history_down": self.history_down,
            "domains": self.domains,
            "last_sni": self.last_sni,
            "is_blocked": self.is_blocked,
            "schedule_start": self.schedule_start,
            "schedule_end": self.schedule_end,
            "last_known_ip": self.last_known_ip,
            "last_seen": self.last_seen
        }

    @classmethod
    def from_dict(cls, data):
        # Handle Category Enum
        try:
            cat = DeviceCategory(data.get("category", "Unknown"))
        except ValueError:
            cat = DeviceCategory.UNKNOWN
            
        dev = cls(
            ip=data.get("ip", ""),
            mac=data.get("mac", ""),
            vendor=data.get("vendor", "Unknown"),
            hostname=data.get("hostname", ""),
            category=cat,
            confidence=data.get("confidence", 0),
            os_guess=data.get("os_guess", ""),
            open_ports=data.get("open_ports", []),
            mdns_services=data.get("mdns_services", []),
            total_up=data.get("total_up", 0),
            total_down=data.get("total_down", 0),
            history_up=data.get("history_up", []),
            history_down=data.get("history_down", []),
            domains=data.get("domains", []),
            last_sni=data.get("last_sni", ""),
            is_blocked=data.get("is_blocked", False),
            schedule_start=data.get("schedule_start", ""),
            schedule_end=data.get("schedule_end", ""),
            last_known_ip=data.get("last_known_ip", ""),
            last_seen=data.get("last_seen", 0.0)
        )
        return dev

class DeviceStore:
    def __init__(self, settings_manager=None):
        import threading
        self.devices: Dict[str, Device] = {} # Keyed by MAC
        self.lock = threading.Lock()
        self.settings = settings_manager # Reference to global settings

    def add_or_update(self, ip: str, mac: str, vendor: str = None):
        now = __import__("time").time()
        
        with self.lock:
            # IP Conflict Resolution: 
            # If this IP is already owned by a DIFFERENT mac, we only take it 
            # if the other mac hasn't been seen for a significant window (e.g. 30s)
            for existing_mac, dev in self.devices.items():
                if dev.ip == ip and existing_mac != mac:
                    # If the existing device was seen very recently (last 30s),
                    # we don't steal the IP yet. This prevents flickering.
                    if now - dev.last_seen < 30:
                        # Continue - let the existing one keep the IP for now
                        pass 
                    else:
                        dev.ip = "" # Clear stale IP since it's "old enough"
            
            if mac in self.devices:
                dev = self.devices[mac]
                # Only take the IP if no one else is currently "locking" it
                active_owner = any(d.ip == ip and d.mac != mac and (now - d.last_seen < 30) for d in self.devices.values())
                if not active_owner:
                    dev.ip = ip
                    if ip: dev.last_known_ip = ip
                
                dev.last_seen = now
                if vendor and (dev.vendor == "Unknown" or dev.vendor == "Private/Random"):
                    dev.vendor = vendor
            else:
                # Only assign IP if not active elsewhere
                active_owner = any(d.ip == ip and (now - d.last_seen < 30) for d in self.devices.values())
                assigned_ip = ip if not active_owner else ""
                
                # Check Paranoid Mode (Auto-Block)
                is_blocked = False
                if self.settings and self.settings.get("paranoid_mode", False):
                    is_blocked = True
                    __import__("logging").info(f"PARANOID MODE: Auto-blocking new device {mac}")

                self.devices[mac] = Device(
                    ip=assigned_ip, 
                    mac=mac, 
                    vendor=vendor or "Unknown",
                    last_known_ip=assigned_ip,
                    last_seen=now,
                    is_blocked=is_blocked
                )
            return self.devices[mac]

    def cleanup_stale_devices(self, threshold_seconds: float):
        """Clears IP for devices not seen in the last X seconds to mark them as stale."""
        now = __import__("time").time()
        with self.lock:
            for dev in self.devices.values():
                if dev.ip and (now - dev.last_seen > threshold_seconds):
                    __import__("logging").info(f"Marking device {dev.mac} ({dev.ip}) as stale due to inactivity timeout.")
                    dev.ip = ""

    def get_all(self) -> List[Device]:
        with self.lock:
            return list(self.devices.values())
            
    def get_snapshot(self) -> Dict[str, Device]:
        """Returns a snapshot of the devices dict for safe iteration outside locks."""
        with self.lock:
            return self.devices.copy()

    def save_to_file(self, filename: str):
        import json
        import logging
        try:
            data = {mac: dev.to_dict() for mac, dev in self.devices.items()}
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
            logging.info(f"Saved {len(data)} devices to {filename}")
        except Exception as e:
            logging.error(f"Failed to save devices: {e}")

    def load_from_file(self, filename: str):
        import json
        import logging
        import os
        if not os.path.exists(filename):
            return
            
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
                
            count = 0
            for mac, dev_data in data.items():
                try:
                    self.devices[mac] = Device.from_dict(dev_data)
                    count += 1
                except Exception as e:
                    logging.error(f"Error loading device {mac}: {e}")
                    
            logging.info(f"Loaded {count} devices from {filename}")
        except Exception as e:
            logging.error(f"Failed to load devices: {e}")
