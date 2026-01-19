import unittest
from unittest.mock import MagicMock, patch
import sys

# Mock scapy before import
sys.modules["scapy"] = MagicMock()
sys.modules["scapy.all"] = MagicMock()
sys.modules["scapy.layers.dns"] = MagicMock()

from src.device_store import Device, DeviceStore
from src.engine.monitor import BandwidthMonitor

class TestBlockingLogic(unittest.TestCase):
    def setUp(self):
        self.store = DeviceStore()
        self.monitor = BandwidthMonitor(self.store, "192.168.1.1")
        self.device = Device(ip="192.168.1.10", mac="00:00:00:00:00:10")
        
    def test_global_kill_switch(self):
        self.monitor.global_kill_switch = True
        self.assertTrue(self.monitor.should_block(self.device), "Should block when global switch is ON")
        
        self.monitor.global_kill_switch = False
        self.assertFalse(self.monitor.should_block(self.device), "Should not block when global switch is OFF")

    def test_manual_block(self):
        self.device.is_blocked = True
        self.assertTrue(self.monitor.should_block(self.device), "Should block when manually blocked")
        
        self.device.is_blocked = False
        self.assertFalse(self.monitor.should_block(self.device), "Should not block when manual block is OFF")

    def test_schedule_simple(self):
        # Schedule is 10:00 to 12:00
        self.device.schedule_start = "10:00"
        self.device.schedule_end = "12:00"
        
        # Test Case: Current Time 11:00 (Inside)
        self.monitor._get_current_time_str = MagicMock(return_value="11:00")
        self.assertTrue(self.monitor.should_block(self.device))
            
        # Test Case: Current Time 09:00 (Outside)
        self.monitor._get_current_time_str = MagicMock(return_value="09:00")
        self.assertFalse(self.monitor.should_block(self.device))

    def test_schedule_overnight(self):
        # Schedule is 22:00 to 06:00
        self.device.schedule_start = "22:00"
        self.device.schedule_end = "06:00"
        
        # Test Case: Current Time 23:00 (Inside)
        self.monitor._get_current_time_str = MagicMock(return_value="23:00")
        self.assertTrue(self.monitor.should_block(self.device))
            
        # Test Case: Current Time 05:00 (Inside)
        self.monitor._get_current_time_str = MagicMock(return_value="05:00")
        self.assertTrue(self.monitor.should_block(self.device))

        # Test Case: Current Time 12:00 (Outside)
        self.monitor._get_current_time_str = MagicMock(return_value="12:00")
        self.assertFalse(self.monitor.should_block(self.device))

if __name__ == '__main__':
    unittest.main()
