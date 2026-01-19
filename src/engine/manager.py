import threading
import logging
import sys
import os
from scapy.all import conf
import netifaces

logger = logging.getLogger(__name__)

class EngineCoordinator:
    def __init__(self, device_store, settings_manager=None):
        self.device_store = device_store
        self.settings = settings_manager
        self.scanner = None
        self.monitor = None
        self.discovery = None
        self.interface = None
        self.gateway_ip = None
        self._running = False

    def _detect_network(self):
        """Robustlly detect the primary interface and gateway."""
        try:
            # 1. Use manual interface if set, else try netifaces for default gateway
            manual_iface = self.settings.get("interface") if self.settings else None
            if manual_iface:
                self.interface = manual_iface
                # We still need gateway IP for monitor
                gws = netifaces.gateways()
                # Try to find gateway for this specific interface
                for gw in gws.get(netifaces.AF_INET, []):
                    if gw[1] == self.interface:
                        self.gateway_ip = gw[0]
                        break
                if not self.gateway_ip:
                    # Fallback to default
                    default_gw = gws.get('default', {}).get(netifaces.AF_INET)
                    if default_gw: self.gateway_ip = default_gw[0]
                
                logger.info(f"Using manual interface: {self.interface} -> {self.gateway_ip}")
                return

            gws = netifaces.gateways()
            default_gw = gws.get('default', {}).get(netifaces.AF_INET)
            if default_gw:
                self.gateway_ip = default_gw[0]
                self.interface = default_gw[1]
                logger.info(f"Detected network via netifaces: {self.interface} -> {self.gateway_ip}")
                return

            # 2. Fallback to Scapy conf
            self.interface = conf.iface
            scapy_gw = getattr(conf, 'gw', None)
            if scapy_gw:
                self.gateway_ip = scapy_gw
            else:
                # 3. Last resort: scan routes
                for route in conf.route.routes:
                    if route[0] == 0 and route[1] == 0:
                        self.gateway_ip = route[2]
                        break
            
            logger.info(f"Detected network via Scapy fallback: {self.interface} -> {self.gateway_ip}")
        except Exception as e:
            logger.error(f"Network detection failed: {e}")
            self.gateway_ip = "192.168.1.1" # Safe default

    def start(self):
        if self._running:
            return
        
        from src.engine.scanner import NetworkScanner
        from src.engine.monitor import BandwidthMonitor
        from src.engine.discovery import DiscoveryListener

        self._detect_network()
        
        logger.info("Starting networking engines...")
        
        try:
            scan_interval = self.settings.get("scan_interval", 30) if self.settings else 30
            self.scanner = NetworkScanner(self.device_store, interface=self.interface, scan_interval=scan_interval)
            self.monitor = BandwidthMonitor(self.device_store, gateway_ip=self.gateway_ip, interface=self.interface)
            self.discovery = DiscoveryListener(self.device_store)

            self.scanner.start()
            self.monitor.start()
            self.discovery.start()
            
            self._running = True
            logger.info("All engines started successfully.")
        except Exception as e:
            logger.error(f"Startup failed: {e}")
            if "bpf" in str(e).lower() or "permission" in str(e).lower():
                logger.error("CRITICAL: Permission denied for raw socket access. Please run as root (sudo).")

    def stop(self):
        if not self._running:
            return
        
        logger.info("Stopping engines...")
        self._running = False
        
        if self.scanner:
            self.scanner.stop()
        if self.monitor:
            self.monitor.running = False
        if self.discovery:
            self.discovery.stop()
            
        # Join threads with timeout to avoid hangs
        for engine, name in [(self.scanner, "Scanner"), (self.monitor, "Monitor"), (self.discovery, "Discovery")]:
            if engine and engine.is_alive():
                engine.join(timeout=2.0)
                if engine.is_alive():
                    logger.warning(f"{name} thread did not exit gracefully.")
        
        logger.info("Stopped networking engines.")

    def update_settings(self, new_settings):
        """Update live engines with new settings where possible."""
        if not self._running: return
        
        if "scan_interval" in new_settings and self.scanner:
            self.scanner.scan_interval = int(new_settings["scan_interval"])
            logger.info(f"Updated scan interval to {self.scanner.scan_interval}s")
        
        if "interface" in new_settings:
            # Interface change usually requires a restart, but we'll log it for now
            # In a full impl, we might call stop() and start() again
            logger.warning("Interface changed in settings. Restart required for full effect.")
