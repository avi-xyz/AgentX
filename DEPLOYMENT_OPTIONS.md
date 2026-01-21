# Deployment Alternatives

While the Raspberry Pi 5 is the flagship recommendation for AgentX, you can run it on any Linux or macOS system that is always on. Here are the most common simple and continuous ways to deploy it on your network.

## Comparison Table

| Method | Ease of Setup | Power Efficiency | Best For | Requirement |
| :--- | :--- | :--- | :--- | :--- |
| **Raspberry Pi** | Medium | ⭐⭐⭐⭐⭐ | Dedicated monitoring | Raspberry Pi 4/5 |
| **Docker (NAS)** | Easy | ⭐⭐⭐⭐ | Integration into home lab | Synology, QNAP, Unraid |
| **Mini PC (NUC)** | Medium | ⭐⭐⭐ | High-performance networks | Intel NUC, Beelink, etc. |
| **Old Laptop** | Easy | ⭐⭐ | Repurposing idle hardware | Any laptop with Ethernet |
| **Mac/PC (Always-on)** | Easiest | ⭐ | Testing or temporary use | Desktop/Server hardware |

---

## 1. Docker (The Easiest Continuous Method)
If you have a NAS (like Synology or QNAP) or an always-on server running Docker, this is the most streamlined way to keep AgentX running.

### Advantages
- Persistent storage for device lists.
- Restarts automatically with the host.
- Isolated environment.

### Setup
See the [Docker Guide](README.md#docker-setup) in the main README.
> [!IMPORTANT]
> Docker **must** be run with `--net=host` and `--privileged` to allow AgentX to perform ARP spoofing and capture network packets.

---

## 2. Mini PCs / NUCs
Small, low-power PCs are often more powerful than a Raspberry Pi and can run a standard Ubuntu or Debian installation.

### Setup
1. Install **Ubuntu Server LTS**.
2. Run the [Standard Linux Setup](README.md#setup).
3. Use the `systemd` service approach described in the [Raspberry Pi Guide](RASPBERRY_PI.md#automatic-startup-systemd) to ensure it runs continuously.

---

## 3. Repurposing an Old Laptop
An old laptop with an Ethernet port is an excellent "free" Raspberry Pi alternative. The built-in screen/keyboard can also act as a local console.

### Tips
- **Disable Sleep**: Ensure the laptop doesn't go to sleep when the lid is closed.
- **Ethernet is King**: Avoid using Wi-Fi for monitoring; ARP spoofing is significantly more reliable over a wired connection.
- **Battery as UPS**: The laptop battery acts as a built-in UPS during power flickers.

---

## 4. Mac Mini / Always-on Desktop
If you have a Mac Mini or a PC that never turns off, you can simply run AgentX in the background.

### Setup
- On macOS, you can use `launchd` to keep the process running.
- On Linux/Windows (WSL2), use `systemd` or `Docker`.
