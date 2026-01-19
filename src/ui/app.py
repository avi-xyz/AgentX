from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, DataTable, Static, Label, Sparkline, Input, Button, Switch
from textual.screen import Screen
from textual.containers import Container, Horizontal, Vertical
from textual.reactive import reactive
from src.device_store import DeviceStore, Device
from src.engine.scanner import NetworkScanner
from src.engine.monitor import BandwidthMonitor
from src.engine.discovery import DiscoveryListener
import threading
import time

class DeviceTable(DataTable):
    def on_mount(self):
        self.cursor_type = "row"
        self.add_columns("IP", "MAC", "Vendor", "Category", "Confidence", "Activity", "Up (KB/s)", "Down (KB/s)")

class DeviceDetailScreen(Screen):
    BINDINGS = [("escape", "app.pop_screen", "Back")]

    def __init__(self, device: Device, on_save_callback=None):
        super().__init__()
        self.device = device
        self.on_save_callback = on_save_callback

    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(
            Label(f"Device: {self.device.hostname or self.device.ip} ({self.device.vendor})", classes="header"),
            Label(f"MAC: {self.device.mac}"),
            Label(f"Category: {self.device.category.value}"),
            Static(" "),
            Label("Bandwidth History (Upload / Download)"),
            Label("Upload History"),
            Sparkline(self.device.history_up, summary_function=max),
            Label("Download History"),
            Sparkline(self.device.history_down, summary_function=max),
            Static(" "),
            Label("Discovered Services:"),
            Static("\n".join(self.device.mdns_services) or "None"),
            Static(" "),
            Label("Recent Domains (SNI/DNS):"),
            Static("\n".join(list(self.device.domains)[-20:]) or "None"),
            Static(" "),
            Label("Scheduled Downtime (HH:MM)"),
            Horizontal(
                Input(placeholder="Start 22:00", id="sched_start", value=self.device.schedule_start, classes="input-time"),
                Input(placeholder="End 07:00", id="sched_end", value=self.device.schedule_end, classes="input-time"),
                classes="sched-row"
            ),
            Button("Save Schedule", id="btn_save_schedule", variant="primary"),
            classes="detail-container"
        )
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_save_schedule":
            start = self.query_one("#sched_start", Input).value
            end = self.query_one("#sched_end", Input).value
            self.device.schedule_start = start
            self.device.schedule_end = end
            self.app.notify(f"Schedule saving for {self.device.ip}")
            if self.on_save_callback:
                self.on_save_callback()

class NetworkApp(App):
    CSS = """
    Screen {
        layout: horizontal;
    }
    #sidebar {
        width: 25;
        dock: left;
        background: $panel;
        padding: 1;
    }
    #main {
        width: 100%;
        height: 100%;
    }
    DataTable {
        height: 100%;
    }
    .stat-box {
        margin-bottom: 2;
        border: solid $accent;
    }
    .detail-container {
        padding: 2;
        height: 100%;
        overflow-y: auto;
    }
    .header {
        text-style: bold;
        padding-bottom: 1;
    }
    .input-time {
        width: 16;
        margin-right: 1;
    }
    .sched-row {
        height: auto;
        margin-bottom: 1;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("s", "scan", "Force Scan"),
        ("x", "toggle_block", "Block/Unblock"),
        ("d", "show_details", "Details"),
        ("enter", "show_details", "Details")
    ]

    def __init__(self):
        super().__init__()
        self.device_store = DeviceStore()
        # Initialize engines
        self.scanner = NetworkScanner(self.device_store, scan_interval=10)
        
        # Get Gateway IP dynamically
        import netifaces
        gateway_ip = "192.168.1.1" # Fallback
        try:
             gws = netifaces.gateways()
             default_gw = gws.get('default', {}).get(netifaces.AF_INET)
             if default_gw:
                 gateway_ip = default_gw[0]
        except:
            pass
            
        self.monitor = BandwidthMonitor(self.device_store, gateway_ip=gateway_ip) 
        self.discovery = DiscoveryListener(self.device_store)
        
        # Add Self
        import netifaces
        try:
            iface = self.scanner.interface
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_LINK in addrs and netifaces.AF_INET in addrs:
                mac = addrs[netifaces.AF_LINK][0]['addr']
                ip = addrs[netifaces.AF_INET][0]['addr']
                myself = self.device_store.add_or_update(ip, mac, "Apple (Host)")
                try:
                    myself.category = self.device_store.devices[mac].category 
                except:
                    pass
                from src.device_store import DeviceCategory
                myself.category = DeviceCategory.PC
                myself.hostname = "My Mac"
        except:
            pass
        
        self.last_update = time.time()
        self.device_snapshots = {} # MAC -> (last_up, last_down)

    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(
            Vertical(
                Static("Devices Found: 0", id="stat_count", classes="stat-box"),
                Static("Network Speed", classes="stat-box"),
                Label("Total Up: 0 KB/s", id="lbl_total_up"),
                Label("Total Down: 0 KB/s", id="lbl_total_down"),
                
                Static(" "),
                Label("Global Controls", classes="header"),
                Horizontal(
                    Label("Kill Switch "),
                    Switch(value=False, id="sw_kill_switch")
                ),
                
                id="sidebar"
            ),
            Container(
                DeviceTable(id="device_table"),
                id="main"
            )
        )
        yield Footer()

    def on_switch_changed(self, event: Switch.Changed) -> None:
        if event.switch.id == "sw_kill_switch":
            self.monitor.global_kill_switch = event.value
            state = "ENABLED" if event.value else "DISABLED"
            self.notify(f"Global Kill Switch {state}", severity="warning" if event.value else "information")
            self.update_ui()

    def on_mount(self):
        # Load existing devices
        self.device_store.load_from_file("devices.json")
        
        self.scanner.start()
        self.monitor.start() # Safe to start, won't spoof until enabled
        self.discovery.start()
        self.set_interval(1, self.update_ui)
        self.set_interval(30, self.auto_save)

    def auto_save(self):
        self.device_store.save_to_file("devices.json")
        
    def action_toggle_block(self):
        table = self.query_one(DeviceTable)
        try:
             # Robust way to get selected row key
             if table.cursor_coordinate:
                 cell_key = table.coordinate_to_cell_key(table.cursor_coordinate)
                 row_key = cell_key.row_key
                 
                 if row_key:
                     mac = row_key.value # row_key is a RowKey object, value is the MAC string
                     if mac in self.device_store.devices:
                         dev = self.device_store.devices[mac]
                         dev.is_blocked = not dev.is_blocked
                         
                         if dev.is_blocked:
                             status = "BLOCKED 🚫"
                             self.monitor.block_target(dev.ip) # Ensure it's in target list
                         else:
                             status = "Unblocked ✅"
                             # Force immediate ARP recovery
                             threading.Thread(target=self.monitor.unblock_target, args=(dev.ip,)).start()
                         
                         self.notify(f"{status}: {dev.ip}")
                         
                         # Force immediate UI update
                         self.update_ui()
        except Exception as e:
            self.notify(f"Error toggling block: {e}", severity="error")
    def action_show_details(self):
        table = self.query_one(DeviceTable)
        if table.cursor_coordinate:
             cell_key = table.coordinate_to_cell_key(table.cursor_coordinate)
             row_key = cell_key.row_key
             if row_key:
                 mac = row_key.value
                 if mac in self.device_store.devices:
                     dev = self.device_store.devices[mac]
                     # Pass save callback to persist schedule immediately
                     self.push_screen(DeviceDetailScreen(dev, on_save_callback=self.auto_save))

    def update_ui(self):
        table = self.query_one(DeviceTable)
        now = time.time()
        
        # Filter: Keep all devices that have an IP OR were seen in the last 5 minutes
        # This prevents the list from shrinking and growing rapidly.
        devices = [d for d in self.device_store.get_all() if d.ip or (now - d.last_seen < 300)]
        
        # Update Stats
        self.query_one("#stat_count", Static).update(f"Devices Found: {len(devices)}")
        
        current_time = time.time()
        dt = current_time - self.last_update
        if dt <= 0: return

        total_up_rate = 0.0
        total_down_rate = 0.0

        # Update Table
        active_macs = {dev.mac for dev in devices}
        rows_to_remove = []
        for row_key in table.rows:
            if row_key.value not in active_macs:
                rows_to_remove.append(row_key)
        
        for rk in rows_to_remove:
            table.remove_row(rk)

        existing_keys = {row_key.value for row_key in table.rows}
        
        for dev in devices:
            # Auto-enable monitoring for demo purposes
            if dev.ip:
                self.monitor.enable_monitoring(dev.ip)

            # Calculate Rate
            last_stats = self.device_snapshots.get(dev.mac, (0, 0))
            delta_up = dev.total_up - last_stats[0]
            delta_down = dev.total_down - last_stats[1]
            
            # Simple rate calc
            up_kbs = (delta_up / dt) / 1024
            down_kbs = (delta_down / dt) / 1024
            
            dev.upload_rate = up_kbs
            dev.download_rate = down_kbs
            
            total_up_rate += up_kbs
            total_down_rate += down_kbs
            
            # Update History (Limit 60)
            dev.history_up.append(up_kbs)
            if len(dev.history_up) > 60: dev.history_up.pop(0)
            dev.history_down.append(down_kbs)
            if len(dev.history_down) > 60: dev.history_down.pop(0)
            
            # Update Snapshot
            self.device_snapshots[dev.mac] = (dev.total_up, dev.total_down)
            
            # Determine Category Display (Blocked status overrides)
            category_display = dev.category.value
            if dev.is_blocked:
                category_display = "🚫 BLOCKED"
            
            # Check Schedule (Visual indicator)
            if self.monitor.should_block(dev) and not dev.is_blocked:
                category_display = "⏰ SCHED BLOCKED"
            
            # Handle No IP / Stale entries
            display_ip = dev.ip
            if not display_ip:
                display_ip = f"({dev.last_known_ip})" if dev.last_known_ip else "(Disconnected)"
                category_display = "⚪️ STALE/ROTATED"

            # Render Row
            row_data = [
                display_ip,
                dev.mac,
                dev.vendor[:15], # Truncate
                category_display,
                f"{dev.confidence}%",
                dev.last_sni[:25], # Truncate domain
                f"{up_kbs:.1f}",
                f"{down_kbs:.1f}"
            ]
            
            if dev.mac in existing_keys:
                # Update row
                cols = list(table.columns.keys())
                
                # Update specific cells
                table.update_cell(dev.mac, cols[0], display_ip)
                table.update_cell(dev.mac, cols[2], dev.vendor[:15])
                table.update_cell(dev.mac, cols[3], category_display)
                table.update_cell(dev.mac, cols[4], f"{dev.confidence}%")
                table.update_cell(dev.mac, cols[5], dev.last_sni[:25])
                table.update_cell(dev.mac, cols[6], f"{up_kbs:.1f}")
                table.update_cell(dev.mac, cols[7], f"{down_kbs:.1f}")
            else:
                table.add_row(*row_data, key=dev.mac)

        # Update Totals
        self.query_one("#lbl_total_up", Label).update(f"Total Up: {total_up_rate:.1f} KB/s")
        self.query_one("#lbl_total_down", Label).update(f"Total Down: {total_down_rate:.1f} KB/s")
        
        self.last_update = current_time

    def on_unmount(self):
        self.scanner.stop()
        self.monitor.running = False
        self.discovery.stop()
        self.device_store.save_to_file("devices.json")

if __name__ == "__main__":
    app = NetworkApp()
    app.run()
