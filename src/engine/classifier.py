import logging
import re
from src.device_store import Device, DeviceCategory

class DeviceClassifier:
    def __init__(self):
        # Weighted Keyword Map: (Category, Confidence Bonus)
        self.vendor_map = {
            # Mobile
            "apple": (DeviceCategory.MOBILE, 50), # Ambiguous (Mac vs iPhone)
            "samsung": (DeviceCategory.MOBILE, 40), # Ambiguous (TV vs Phone)
            "google": (DeviceCategory.MOBILE, 50),
            "xiaomi": (DeviceCategory.MOBILE, 60),
            "oppo": (DeviceCategory.MOBILE, 70),
            "vivo": (DeviceCategory.MOBILE, 70),
            "oneplus": (DeviceCategory.MOBILE, 80),
            "motorola": (DeviceCategory.MOBILE, 80),
            "huawei": (DeviceCategory.MOBILE, 50),
            
            # PC/Laptop
            "intel": (DeviceCategory.PC, 60),
            "dell": (DeviceCategory.PC, 80),
            "hp": (DeviceCategory.PC, 80),
            "lenovo": (DeviceCategory.PC, 80),
            "microsoft": (DeviceCategory.PC, 80),
            "msi": (DeviceCategory.PC, 90),
            "asus": (DeviceCategory.PC, 70),
            "acer": (DeviceCategory.PC, 80),
            "razer": (DeviceCategory.PC, 90),
            
            # IoT / Smart Home
            "espressif": (DeviceCategory.IOT, 90),
            "tuya": (DeviceCategory.IOT, 90),
            "nest": (DeviceCategory.IOT, 90),
            "ring": (DeviceCategory.IOT, 90),
            "wyze": (DeviceCategory.IOT, 90),
            "belkin": (DeviceCategory.IOT, 80),
            "lifx": (DeviceCategory.IOT, 95),
            "philips lighting": (DeviceCategory.IOT, 95),
            "signify": (DeviceCategory.IOT, 90), # Philips Hue
            "google home": (DeviceCategory.IOT, 95),
            "amazon technologies": (DeviceCategory.IOT, 60), # Echo or Kindle
            "ecobee": (DeviceCategory.IOT, 95),
            "august": (DeviceCategory.IOT, 95),
            "lutron": (DeviceCategory.IOT, 95),
            
            # Media
            "roku": (DeviceCategory.MEDIA, 95),
            "sonos": (DeviceCategory.MEDIA, 95),
            "vizio": (DeviceCategory.MEDIA, 90),
            "lg electronics": (DeviceCategory.MEDIA, 70), # Likely TV
            "tcl": (DeviceCategory.MEDIA, 80), # TV
            "hisense": (DeviceCategory.MEDIA, 80),
            "nvidia": (DeviceCategory.MEDIA, 60), # Shield or GPU?
            "bose": (DeviceCategory.MEDIA, 90),
            
            # Networking
            "cisco": (DeviceCategory.ROUTER, 80),
            "ubiquiti": (DeviceCategory.ROUTER, 80),
            "netgear": (DeviceCategory.ROUTER, 80),
            "synology": (DeviceCategory.SERVER, 80),
            "qnap": (DeviceCategory.SERVER, 80),
            "raspberry": (DeviceCategory.SERVER, 90),
            
            # Game Consoles
            "nintendo": (DeviceCategory.MEDIA, 95),
            "sony interactive": (DeviceCategory.MEDIA, 90), # PlayStation
        }
        
    def classify(self, device: Device, tcp_signature: dict = None) -> DeviceCategory:
        cat = DeviceCategory.UNKNOWN
        confidence = 0
        
        vendor_lower = device.vendor.lower() if device.vendor else ""
        name_lower = device.hostname.lower()
        
        # 1. Vendor Analysis
        for key, (category, score) in self.vendor_map.items():
            if key in vendor_lower:
                cat = category
                confidence = score
                break
        
        # 2. Refinements based on Name/Ambiguity
        if cat == DeviceCategory.MOBILE:
            if "tv" in name_lower:
                cat = DeviceCategory.MEDIA
                confidence = 90
            elif "macbook" in name_lower or "imac" in name_lower:
                cat = DeviceCategory.PC
                confidence = 95
        
        elif cat == DeviceCategory.PC:
            if "android" in name_lower: # Intel/Asus Android devices?
                cat = DeviceCategory.MOBILE
        
        elif "apple" in vendor_lower:
             # Apple is tricky. Default to Mobile (iPhone is most common)
             # But check OUI ranges? (To Hard). Check Name.
             if "mac" in name_lower:
                 cat = DeviceCategory.PC
                 confidence = 80
             elif "phone" in name_lower or "pad" in name_lower:
                 cat = DeviceCategory.MOBILE
                 confidence = 90
             elif "watch" in name_lower:
                 cat = DeviceCategory.MOBILE # Wearable
                 confidence = 95
             elif "tv" in name_lower:
                 cat = DeviceCategory.MEDIA
                 confidence = 95
             elif cat == DeviceCategory.UNKNOWN:
                 cat = DeviceCategory.MOBILE # Probability
                 confidence = 40

        # 3. Special Cases (Private MAC)
        if device.vendor == "Private/Random":
            cat = DeviceCategory.MOBILE # 99% of random MACs are phones
            confidence = 60 # Pretty sure, but could be a laptop

        # 4. Service Discovery overrides (Strongest signal)
        if hasattr(device, 'mdns_services'):
            for svc in device.mdns_services:
                if "googlecast" in svc:
                    cat = DeviceCategory.MEDIA
                    confidence = 99
                if "printer" in svc or "ipp" in svc:
                    cat = DeviceCategory.PRINTER
                    confidence = 99
        
        # Final Assignment
        if cat != DeviceCategory.UNKNOWN and confidence == 0:
            confidence = 50 # Default baseline if matched
            
        return cat, confidence
