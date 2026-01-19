import sys
import time
import logging
from src.device_store import DeviceStore
from src.engine.scanner import NetworkScanner

from src.ui.app import NetworkApp

# Configure logging
logging.basicConfig(filename='network_inspector.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "test-scan":
        print("Starting Network Scanner Test (Needs Root for ARP)...")
        store = DeviceStore()
        scanner = NetworkScanner(store, scan_interval=5)
        scanner.start()
        
        try:
            for _ in range(3): # Run for 15 seconds
                time.sleep(5)
                devices = store.get_all()
                print(f"\n--- Found {len(devices)} Devices ---")
                for dev in devices:
                    print(f"{dev.ip: <15} {dev.mac: <18} {dev.vendor}")
        except KeyboardInterrupt:
            pass
        finally:
            scanner.stop()
            scanner.join()
    else:
        # Run UI
        app = NetworkApp()
        app.run()

if __name__ == "__main__":
    main()
