import netifaces
from scapy.all import conf, get_if_list

print(f"Scapy Default Interface: {conf.iface}")
print(f"Scapy Interface List: {get_if_list()}")

print("\nNetifaces Details:")
for iface in netifaces.interfaces():
    print(f"Interface: {iface}")
    try:
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            for link in addrs[netifaces.AF_INET]:
                print(f"  IPv4: {link['addr']} Mask: {link['netmask']}")
    except Exception as e:
        print(f"  Error: {e}")

# Try to find default gateway
try:
    gws = netifaces.gateways()
    print(f"\nGateways: {gws}")
    default = gws.get('default', {}).get(netifaces.AF_INET)
    print(f"Default IPv4 Gateway: {default}")
except:
    print("Could not get gateways")
