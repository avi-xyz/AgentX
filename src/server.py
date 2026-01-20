import asyncio
import logging
import os
import time
from typing import List, Dict, Optional
import threading
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from src.device_store import DeviceStore, DeviceCategory
from src.engine.manager import EngineCoordinator
from src.settings_manager import SettingsManager

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI(title="AgentX Network Inspector")

# CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Shared State
settings_manager = SettingsManager()
device_store = DeviceStore(settings_manager)
device_store.load_from_file("devices.json")

# Engine Manager
coordinator = EngineCoordinator(device_store, settings_manager)

@app.on_event("startup")
async def startup_event():
    # Start engines in a separate thread to keep web server responsive
    threading.Thread(target=coordinator.start, daemon=True).start()
    logger.info("FastAPI startup: Engines delegated to background.")

@app.on_event("shutdown")
async def shutdown_event():
    coordinator.stop()
    device_store.save_to_file("devices.json")
    logger.info("Engines stopped and state saved.")

# Helper to get engines safety (for API endpoints)
def get_monitor():
    return coordinator.monitor

def get_scanner():
    return coordinator.scanner

# API Models
class BlockRequest(BaseModel):
    mac: str
    blocked: bool

class ScheduleRequest(BaseModel):
    mac: str
    start: str
    end: str

class SettingsUpdate(BaseModel):
    interface: Optional[str] = None
    scan_interval: Optional[int] = None
    paranoid_mode: Optional[bool] = None

# Endpoints
@app.get("/api/devices")
async def get_devices():
    return [dev.to_dict() for dev in device_store.get_all()]

@app.post("/api/block")
async def toggle_block(req: BlockRequest):
    monitor = get_monitor()
    target_ip = None
    
    with device_store.lock:
        if req.mac not in device_store.devices:
            raise HTTPException(status_code=404, detail="Device not found")
            
        dev = device_store.devices[req.mac]
        dev.is_blocked = req.blocked
        target_ip = dev.ip
        status = {"status": "ok", "mac": req.mac, "is_blocked": dev.is_blocked}
    
    # Perform networking operations outside the lock and offload blocking calls
    if target_ip and monitor:
        if req.blocked:
            # enable_monitoring is fast (just adds to a set)
            monitor.enable_monitoring(target_ip)
            logger.info(f"Enabled active blocking for {target_ip} ({req.mac})")
        else:
            # disable_monitoring is fast
            monitor.disable_monitoring(target_ip)
            # unblock_target is SLOW (1s). Offload to a background thread to keep EL responsive.
            asyncio.create_task(asyncio.to_thread(monitor.unblock_target, target_ip))
            logger.info(f"Triggered background unblock for {target_ip} ({req.mac})")
            
    return status

@app.post("/api/schedule")
async def update_schedule(req: ScheduleRequest):
    with device_store.lock:
        if req.mac in device_store.devices:
            dev = device_store.devices[req.mac]
            dev.schedule_start = req.start
            dev.schedule_end = req.end
            logger.info(f"Updated schedule for {req.mac}: {req.start} to {req.end}")
            return {"status": "ok", "mac": req.mac, "schedule_start": dev.schedule_start, "schedule_end": dev.schedule_end}
    raise HTTPException(status_code=404, detail="Device not found")

@app.post("/api/kill-switch")
async def toggle_global_kill_switch(enabled: bool):
    monitor = get_monitor()
    if monitor:
        monitor.global_kill_switch = enabled
    return {"status": "ok", "global_kill_switch": enabled}

@app.get("/api/stats")
async def get_global_stats():
    monitor = get_monitor()
    devices = device_store.get_all()
    active_count = len([d for d in devices if d.ip])
    total_up = sum(d.upload_rate for d in devices)
    total_down = sum(d.download_rate for d in devices)
    return {
        "active_devices": active_count,
        "total_up_kbps": round(total_up, 2),
        "total_down_kbps": round(total_down, 2),
        "global_kill_switch": monitor.global_kill_switch if monitor else False
    }

@app.get("/api/settings")
async def get_settings():
    import netifaces
    interfaces = netifaces.interfaces()
    return {
        "settings": settings_manager.settings,
        "available_interfaces": interfaces
    }

@app.post("/api/settings")
async def update_settings(req: SettingsUpdate):
    update_data = {k: v for k, v in req.dict().items() if v is not None}
    settings_manager.update(update_data)
    coordinator.update_settings(update_data)
    return {"status": "ok", "settings": settings_manager.settings}

# WebSocket for Real-time Updates
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                pass

manager = ConnectionManager()

@app.websocket("/ws/updates")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        last_stats_map = {} # mac -> (total_up, total_down)
        last_time = time.time()
        
        while True:
            await asyncio.sleep(2) # Update every 2 seconds
            now = time.time()
            dt = now - last_time
            if dt <= 0: continue
            
            # Cleanup stale devices (no traffic/scan for 60s)
            device_store.cleanup_stale_devices(60)
            
            # Snapshot devices to avoid blocking other threads with long lock holds
            devices_map = device_store.get_snapshot()
            updates = []
            
            total_up_rate = 0.0
            total_down_rate = 0.0
            
            # Use monitor snapshot to avoid repeated coordinator access
            monitor = get_monitor()

            for mac, dev in devices_map.items():
                # Calculate Rates
                prev_up, prev_down = last_stats_map.get(mac, (dev.total_up, dev.total_down))
                
                up_rate = ((dev.total_up - prev_up) / dt) / 1024
                down_rate = ((dev.total_down - prev_down) / dt) / 1024
                
                dev.upload_rate = up_rate
                dev.download_rate = down_rate
                
                last_stats_map[mac] = (dev.total_up, dev.total_down)
                
                total_up_rate += up_rate
                total_down_rate += down_rate
                
                # Auto-monitor enabled IPs (only if monitor is ready)
                if monitor and dev.ip and dev.ip not in monitor.targets:
                    monitor.enable_monitoring(dev.ip)

                updates.append({
                    "mac": dev.mac,
                    "ip": dev.ip or f"({dev.last_known_ip})",
                    "vendor": dev.vendor,
                    "category": dev.category.value if not dev.is_blocked else "🚫 BLOCKED",
                    "up_rate": round(up_rate, 1),
                    "down_rate": round(down_rate, 1),
                    "is_blocked": dev.is_blocked,
                    "is_stale": not dev.ip,
                    "domains": list(dev.domains)[-10:] # Last 10 domains
                })
            
            last_time = now
            await websocket.send_json({
                "type": "device_update",
                "devices": updates,
                "global_stats": {
                    "total_up": round(total_up_rate, 1),
                    "total_down": round(total_down_rate, 1),
                    "kill_switch": get_monitor().global_kill_switch if get_monitor() else False
                }
            })
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Mount Static Files
static_path = os.path.join(os.path.dirname(__file__), "static")
if not os.path.exists(static_path):
    os.makedirs(static_path)

app.mount("/", StaticFiles(directory=static_path, html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
