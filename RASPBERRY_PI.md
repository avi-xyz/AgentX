# Deploying AgentX on Raspberry Pi

AgentX is designed to run efficiently on Raspberry Pi hardware for 24/7 network monitoring and security.

## Recommended Hardware
*   **Raspberry Pi 5 (4GB or 8GB)**: Recommended for best performance.
*   **Raspberry Pi 4 Model B (2GB+)**: Minimum recommended version.
*   **Ethernet Connection**: Highly recommended for stable ARP spoofing and network monitoring.
*   **High-Quality Power Supply**: Official Raspberry Pi power supply is recommended to avoid low-voltage warnings under heavy network load.

## System Preparation

### 1. OS Installation
Install **Raspberry Pi OS Lite (64-bit)** using the [Raspberry Pi Imager](https://www.raspberrypi.com/software/).

### 2. Install System Dependencies
In the terminal, run:
```bash
sudo apt update
sudo apt install -y git python3-pip python3-venv build-essential python3-dev libpcap-dev
```

### 3. Clone and Setup AgentX
```bash
git clone https://github.com/avi-xyz/AgentX.git
cd AgentX

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python requirements
pip install -r requirements.txt
```

## Running AgentX

### Standard Run
To start the dashboard manually:
```bash
sudo ./venv/bin/python3 -m uvicorn src.server:app --host 0.0.0.0 --port 8000
```
> [!IMPORTANT]
> `sudo` is required to allow the application to process raw network packets and perform ARP operations.

### Automatic Startup (systemd)
To ensure AgentX starts on boot and restarts after failure, create a service file:
```bash
sudo nano /etc/systemd/system/agentx.service
```

Paste the following (adjusting `/home/pi/AgentX` to your actual path):
```ini
[Unit]
Description=AgentX Network Inspector
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/pi/AgentX
ExecStart=/home/pi/AgentX/venv/bin/python3 -m uvicorn src.server:app --host 0.0.0.0 --port 8000
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo systemctl enable agentx.service
sudo systemctl start agentx.service
```

## Network Configuration
1.  **Dashboard Access**: Visit `http://[YOUR-PI-IP]:8000` in your web browser.
2.  **Interface Selection**: Go to **Settings** and ensure the correct interface (usually `eth0`) is selected.
3.  **Persistence**: AgentX saves its state to `devices.json` and `settings.json` in the application directory.
