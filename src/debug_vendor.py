from mac_vendor_lookup import MacLookup
import sys

def test_lookup():
    print("Initializing MacLookup...")
    mac = MacLookup()
    
    print("Updating vendors...")
    import os
    # Same path as app
    cache_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "engine/mac-vendors.txt")
    print(f"Target path: {cache_path}")
    
    try:
        mac.update_vendors(cache_path)
        print("Vendor update successful.")
    except Exception as e:
        print(f"Vendor update failed: {type(e).__name__}: {e}")

    try:
        # Test with a known Apple MAC
        test_mac = "00:09:5B:00:00:00" # Netgear ... wait, let's use a real one.
        # Apple: 00:1B:63
        test_mac = "00:1B:63:00:00:00"
        vendor = mac.lookup(test_mac)
        print(f"Lookup {test_mac}: {vendor}")
    except Exception as e:
        print(f"Lookup failed: {e}")

if __name__ == "__main__":
    test_lookup()
