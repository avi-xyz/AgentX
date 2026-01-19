import time
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("debug")

print("Stage 1: Starting Gateway Detection Test")
gateway_ip = "192.168.1.1"

try:
    print("Stage 2: Importing Scapy conf")
    start = time.time()
    from scapy.all import conf
    print(f"Scapy import took {time.time() - start:.2f}s")
    
    # Robust Scapy Gateway Detection
    print("Stage 3: Checking conf.gw")
    scapy_gw = getattr(conf, 'gw', None)
    if scapy_gw:
        gateway_ip = scapy_gw
        print(f"Detected gateway from Scapy: {gateway_ip}")
    else:
        print("Stage 4: Checking netifaces")
        import netifaces
        gws = netifaces.gateways()
        default_gw = gws.get('default', {}).get(netifaces.AF_INET)
        if default_gw:
            gateway_ip = default_gw[0]
            print(f"Detected gateway from netifaces: {gateway_ip}")
        else:
            print("Stage 5: Checking Scapy routes")
            # This is the suspect call
            start = time.time()
            routes = conf.route.routes
            print(f"Route access took {time.time() - start:.2f}s")
            for route in routes:
                if route[0] == 0 and route[1] == 0: # 0.0.0.0/0
                    gateway_ip = route[2]
                    print(f"Detected gateway from Scapy routes: {gateway_ip}")
                    break
except Exception as e:
    print(f"Error: {e}")

print(f"Final Gateway: {gateway_ip}")
